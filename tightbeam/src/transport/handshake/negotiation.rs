//! Security profile and transport negotiation for TightBeam handshakes.
//!
//! The offer and accept structures carry algorithm and mux capability as DER
//! values, so negotiation runs before any concrete crypto exists. The server
//! and client helpers derive clamped [`MuxSettings`] and consult the optional
//! [`TransportAuthorizer`] and [`ProfileStrengthPolicy`] hooks.

#[cfg(not(feature = "std"))]
extern crate alloc;
#[cfg(not(feature = "std"))]
use alloc::boxed::Box;
#[cfg(all(
	not(feature = "std"),
	any(feature = "transport-cms", feature = "transport-ecies")
))]
use alloc::sync::Arc;
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
#[cfg(all(feature = "std", any(feature = "transport-cms", feature = "transport-ecies")))]
use std::sync::Arc;
#[cfg(feature = "std")]
use std::vec::Vec;

use crate::constants::{
	DEFAULT_MUX_CHUNK_SIZE, DEFAULT_MUX_CREDIT_UNIT, DEFAULT_MUX_STREAM_CREDIT, MAX_MUX_STREAM_CAP,
};
use core::marker::PhantomData;

use crate::crypto::common::KeySizeUser;
use crate::crypto::hash::Digest;
use crate::crypto::profiles::{CryptoProvider, SecurityProfileDesc};
use crate::der::asn1::OctetString;
use crate::der::Error as DerDecodeError;
use crate::der::Sequence;
use crate::transport::handshake::receipt::SessionReceipt;
use crate::utils::marker::{MaybeSend, MaybeSendFuture, MaybeSync};
use crate::Beamable;

#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
use crate::constants::{MAX_MUX_CHUNK_SIZE, MAX_MUX_SESSION_BUDGET, MAX_MUX_STREAM_CREDIT, MIN_MUX_CHUNK_SIZE};

use crate::Errorizable;

/// Maximum number of profiles accepted in a [`SecurityOffer`].
///
/// The bound limits the pre-authentication O(offer x supported)
/// negotiation scan against offer-flood DoS (CWE-770).
pub const MAX_OFFER_PROFILES: usize = 32;

/// Client security-profile offer, encoded as DER.
///
/// The offer lists the algorithm combinations the client supports, most
/// preferred first. The server selects in *its* local order, so the peer
/// ordering carries no weight (CWE-757).
#[derive(Clone, Debug, Eq, PartialEq, Beamable, Sequence)]
pub struct SecurityOffer {
	/// Security profile descriptors in preference order, most preferred first.
	pub profiles: Vec<SecurityProfileDesc>,
}

impl SecurityOffer {
	/// Creates an offer from `profiles`, most preferred first.
	pub fn new(profiles: impl IntoIterator<Item = SecurityProfileDesc>) -> Self {
		let profiles: Vec<SecurityProfileDesc> = profiles.into_iter().collect();
		Self { profiles }
	}

	/// Creates a one-profile offer with the encoding of a singleton list.
	pub fn single(profile: SecurityProfileDesc) -> Self {
		Self { profiles: Vec::from([profile]) }
	}
}

/// Server security-profile accept, encoded as DER.
///
/// The accept carries the profile the server selected from the client's
/// [`SecurityOffer`] under local preference and any
/// [`ProfileStrengthPolicy`].
#[derive(Clone, Debug, Eq, PartialEq, Beamable, Sequence)]
pub struct SecurityAccept {
	/// The security profile descriptor the server selected.
	pub profile: SecurityProfileDesc,
}

impl SecurityAccept {
	/// Creates an accept for the profile the server selected from the peer
	/// offer.
	pub fn new(profile: SecurityProfileDesc) -> Self {
		Self { profile }
	}
}

/// Per-direction session budgets, in credits.
///
/// A credit is the abstract TightBeam volume unit. A data chunk debits
/// `ceil(payload_len / credit_unit)` credits from its sender's direction.
///
/// # Lifetime
///
/// The budgets are fixed per key epoch and only shrink inside an epoch. The
/// application assigns the value of a credit (free, fiat, or other).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Beamable, Sequence)]
pub struct MuxBudgets {
	/// Credits spendable on client-to-server data chunks.
	pub client_to_server: u64,
	/// Credits spendable on server-to-client data chunks.
	pub server_to_client: u64,
}

impl MuxBudgets {
	/// Returns the componentwise minimum, which is the grant a server derives
	/// from a request under its local ceiling.
	pub fn min(self, ceiling: MuxBudgets) -> MuxBudgets {
		MuxBudgets {
			client_to_server: self.client_to_server.min(ceiling.client_to_server),
			server_to_client: self.server_to_client.min(ceiling.server_to_client),
		}
	}

	/// Clamp both directions to [`MAX_MUX_SESSION_BUDGET`] (CWE-770).
	#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
	fn clamped(self) -> MuxBudgets {
		MuxBudgets {
			client_to_server: self.client_to_server.min(MAX_MUX_SESSION_BUDGET),
			server_to_client: self.server_to_client.min(MAX_MUX_SESSION_BUDGET),
		}
	}
}

/// Client transport capability offer for multiplexing.
///
/// The handshake transcript binds this offer with the client's opening
/// message.
///
/// # Directionality
///
/// Each field advertises what the *sender of this struct* will receive: the
/// peer-initiated stream cap, the inbound chunk size, and the inbound stream
/// credit. The [`requested_budgets`](Self::requested_budgets) and
/// [`authorization`](Self::authorization) fields travel from client to server
/// only.
///
/// # Sources
///
/// - RFC 9113 § 5.1.2, stream concurrency:
///   <https://datatracker.ietf.org/doc/html/rfc9113#section-5.1.2>
#[derive(Clone, Debug, Eq, PartialEq, Beamable, Sequence)]
pub struct TransportOffer {
	/// `true` when the sender supports stream multiplexing.
	pub mux: bool,
	/// Maximum concurrent streams the peer may initiate toward the sender.
	pub max_peer_initiated_streams: u32,
	/// Largest inbound chunk payload the sender of this struct accepts.
	///
	/// The receiver clamps it to `MIN_MUX_CHUNK_SIZE..=MAX_MUX_CHUNK_SIZE`.
	/// Chunking is always on, so no value opts out of it.
	pub chunk_payload_size: u32,
	/// Bytes per session-budget credit that the client proposes. The value in
	/// the [`TransportAccept`] wins.
	pub credit_unit: u32,
	/// Initial per-stream chunk allowance the sender of this struct grants to
	/// inbound streams, clamped to [`MAX_MUX_STREAM_CREDIT`].
	pub initial_stream_credit: u64,
	/// Per-direction session budgets the client requests. `None` requests an
	/// unmetered session with flow control only.
	#[asn1(optional = "true")]
	pub requested_budgets: Option<MuxBudgets>,
	/// Opaque settlement token that the transcript binds and the server's
	/// [`TransportAuthorizer`] consumes. TightBeam treats it as opaque bytes.
	#[asn1(optional = "true")]
	pub authorization: Option<OctetString>,
}

impl TransportOffer {
	/// Create a multiplexing offer advertising the given peer-initiated
	/// cap with default chunking, credit, and unmetered budget settings.
	pub fn mux(max_peer_initiated_streams: u32) -> Self {
		Self {
			mux: true,
			max_peer_initiated_streams,
			chunk_payload_size: DEFAULT_MUX_CHUNK_SIZE,
			credit_unit: DEFAULT_MUX_CREDIT_UNIT,
			initial_stream_credit: DEFAULT_MUX_STREAM_CREDIT,
			requested_budgets: None,
			authorization: None,
		}
	}

	/// Request per-direction budgets for the session.
	#[must_use]
	pub fn with_budgets(mut self, budgets: MuxBudgets) -> Self {
		self.requested_budgets = Some(budgets);
		self
	}

	/// Attach an opaque settlement token for the server's authorizer.
	#[must_use]
	pub fn with_authorization(mut self, token: OctetString) -> Self {
		self.authorization = Some(token);
		self
	}

	/// Advertise the inbound chunk payload ceiling in the offer.
	#[must_use]
	pub fn with_chunk_payload_size(mut self, size: u32) -> Self {
		self.chunk_payload_size = size;
		self
	}

	/// Propose the bytes-per-credit unit. The value in the accept wins.
	#[must_use]
	pub fn with_credit_unit(mut self, unit: u32) -> Self {
		self.credit_unit = unit;
		self
	}

	/// Advertise the initial per-stream chunk allowance granted inbound.
	#[must_use]
	pub fn with_initial_stream_credit(mut self, credit: u64) -> Self {
		self.initial_stream_credit = credit;
		self
	}
}

/// Server transport capability accept for multiplexing.
///
/// The handshake transcript binds this accept with the server's response.
/// It has the directional shape of [`TransportOffer`], so the server
/// advertises what it will *receive*. The accept also sets the terms for
/// both directions in [`credit_unit`](Self::credit_unit) and
/// [`granted_budgets`](Self::granted_budgets).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Beamable, Sequence)]
pub struct TransportAccept {
	/// `true` when the sender supports stream multiplexing.
	pub mux: bool,
	/// Maximum concurrent streams the peer may initiate toward the sender.
	pub max_peer_initiated_streams: u32,
	/// Largest inbound chunk payload the server accepts.
	pub chunk_payload_size: u32,
	/// Bytes per session-budget credit. This value wins for both
	/// directions.
	pub credit_unit: u32,
	/// Initial per-stream chunk allowance the server grants to inbound
	/// streams.
	pub initial_stream_credit: u64,
	/// Per-direction budgets granted for the epoch. `None` means the session
	/// is unmetered.
	#[asn1(optional = "true")]
	pub granted_budgets: Option<MuxBudgets>,
}

/// Negotiated multiplexing settings for one connection endpoint.
///
/// Both endpoints derive their settings from the same clamped offer and
/// accept.
///
/// # Directionality
///
/// Caps, chunk sizes, and stream credit are directional. Each endpoint
/// enforces what it advertised and respects what its peer advertised, so
/// the settings keep both values instead of a symmetric minimum.
///
/// # Sources
///
/// - RFC 9113 § 5.1.2, stream concurrency:
///   <https://datatracker.ietf.org/doc/html/rfc9113#section-5.1.2>
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MuxSettings {
	/// Maximum concurrent streams this endpoint may initiate, as the peer
	/// advertised.
	pub local_initiated_cap: u32,
	/// Maximum concurrent streams the peer may initiate, as this endpoint
	/// advertised.
	pub peer_initiated_cap: u32,
	/// Largest chunk payload this endpoint may send, from the receive size
	/// the peer advertised.
	pub send_chunk_size: u32,
	/// Largest inbound chunk payload this endpoint accepts, as it
	/// advertised.
	pub recv_chunk_size: u32,
	/// Bytes per session-budget credit in both directions, from the accept.
	pub credit_unit: u32,
	/// Initial chunk allowance on each stream this endpoint initiates or
	/// answers toward the peer, as the peer advertised.
	pub initial_send_credit: u64,
	/// Initial chunk allowance this endpoint grants to each inbound stream,
	/// as it advertised.
	pub initial_recv_credit: u64,
	/// Credits spendable on outbound data this epoch. `None` means the
	/// session is unmetered.
	pub send_budget: Option<u64>,
	/// Credits the peer may spend on inbound data this epoch, enforced
	/// locally. `None` means the session is unmetered.
	pub recv_budget: Option<u64>,
}

impl MuxSettings {
	/// Creates settings with equal caps in both directions and default
	/// chunking and credit, for cleartext multiplexing links that skip the
	/// handshake negotiation.
	///
	/// # Budgets
	///
	/// The settings are always unmetered. A cleartext link has no key epoch
	/// to renew, so a spent bound could never recover.
	///
	/// # Contract
	///
	/// Both endpoints MUST configure the same `cap`, or enforcement diverges.
	/// The cap is clamped to [`MAX_MUX_STREAM_CAP`].
	pub fn symmetric(cap: u32) -> Self {
		let cap = clamp_stream_cap(cap);
		Self {
			local_initiated_cap: cap,
			peer_initiated_cap: cap,
			send_chunk_size: DEFAULT_MUX_CHUNK_SIZE,
			recv_chunk_size: DEFAULT_MUX_CHUNK_SIZE,
			credit_unit: DEFAULT_MUX_CREDIT_UNIT,
			initial_send_credit: DEFAULT_MUX_STREAM_CREDIT,
			initial_recv_credit: DEFAULT_MUX_STREAM_CREDIT,
			send_budget: None,
			recv_budget: None,
		}
	}

	/// Static records this endpoint reserves so a graceful drain can finish
	/// after the GoAway fires.
	///
	/// When a limit check trips, the connection can still owe these records:
	///
	/// - Envelopes already queued outbound, at most the channel capacity.
	/// - Response trailers to in-flight peer streams, at most `peer_cap`.
	/// - Drop-guard cancels for pending local streams, at most `local_cap`.
	/// - The GoAway itself, exactly 1.
	///
	/// The total is `2 * (local_cap + peer_cap) + 1`. A hostile peer that
	/// keeps opening streams after the GoAway draws refusal cancels beyond any
	/// bound, and it only exhausts the cipher of its own dying connection.
	///
	/// # Sources
	///
	/// - RFC 9846 § 5.5, AEAD limits: <https://datatracker.ietf.org/doc/html/rfc9846#section-5.5>
	pub fn drain_reserve_records(&self) -> u64 {
		u64::from(self.local_initiated_cap)
			.saturating_add(u64::from(self.peer_initiated_cap))
			.saturating_mul(2)
			.saturating_add(1)
	}

	/// Credits reserved from the outbound session budget for the drain
	/// reserve.
	///
	/// The reserve is [`Self::drain_reserve_records`] priced at the worst-case
	/// per-chunk debit, `ceil(send_chunk_size / credit_unit)`.
	pub fn send_budget_reserve(&self) -> u64 {
		let chunk = u64::from(self.send_chunk_size.max(1));
		let unit = u64::from(self.credit_unit.max(1));
		self.drain_reserve_records().saturating_mul(chunk.div_ceil(unit))
	}

	/// Credits spendable on application data before the budget watermark
	/// opens an in-band renewal, or drains an unrenewable session through
	/// GoAway.
	///
	/// The value is the granted budget minus [`Self::send_budget_reserve`],
	/// so a metering embedder should size invoices against it. It is `None`
	/// when the session is unmetered.
	pub fn usable_send_budget(&self) -> Option<u64> {
		let budget = self.send_budget?;
		Some(budget.saturating_sub(self.send_budget_reserve()))
	}
}

/// Clamp an advertised concurrent-stream cap to [`MAX_MUX_STREAM_CAP`]
/// (CWE-770).
///
/// Both endpoints apply the clamp to the same advertised value, so their
/// directional views stay consistent.
fn clamp_stream_cap(cap: u32) -> u32 {
	cap.min(MAX_MUX_STREAM_CAP)
}

/// Clamp an advertised chunk payload size into
/// `MIN_MUX_CHUNK_SIZE..=MAX_MUX_CHUNK_SIZE`.
///
/// The floor stops tiny advertisements from amplifying record consumption
/// (CWE-770). Chunking is the only send path, so no value opts out.
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
fn clamp_chunk_size(size: u32) -> u32 {
	size.clamp(MIN_MUX_CHUNK_SIZE, MAX_MUX_CHUNK_SIZE)
}

/// Clamp an advertised credit unit to at least one byte so debit arithmetic
/// never divides by zero.
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
fn clamp_credit_unit(unit: u32) -> u32 {
	unit.max(1)
}

/// Clamp an advertised initial stream credit window into
/// `1..=MAX_MUX_STREAM_CREDIT`.
///
/// The ceiling bounds receive memory (CWE-770). The floor of one chunk keeps
/// every stream startable, because credit grants flow only after a first
/// chunk arrives.
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
fn clamp_stream_credit(credit: u64) -> u64 {
	credit.clamp(1, MAX_MUX_STREAM_CREDIT)
}

/// The peer offer and the local configuration for one accept decision.
///
/// Multiplexing activates only when the peer offered it and it is locally
/// enabled. A missing side yields no accept, so both endpoints share the
/// same activation decision.
///
/// # Local configuration
///
/// The local [`TransportOffer`] is the server configuration:
///
/// - Its receive-side values are advertised back to the client.
/// - Its `requested_budgets` is the grant ceiling, combined with the client's
///   request by componentwise minimum.
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
pub(crate) struct TransportNegotiation<'a> {
	/// Client transport offer, when the handshake carried one.
	pub(crate) offer: Option<&'a TransportOffer>,
	/// Server transport configuration, when multiplexing is configured.
	pub(crate) local: Option<&'a TransportOffer>,
}

#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
impl<'a> TransportNegotiation<'a> {
	/// Applies the accept rule that runs before any authorizer.
	///
	/// # Budgets
	///
	/// Budgets are opt-in, because a grant is a signed receipt attestation.
	/// The server grants budgets only under a local ceiling or an authorizer
	/// verdict that overrides this rule, whatever the client requested.
	pub(crate) fn accept(&self) -> Option<TransportAccept> {
		let offer = self.offer?;
		let local = self.local?;
		if !offer.mux || !local.mux {
			return None;
		}

		// This is the single clamp point for the grant, so the accept equals
		// what the transport enforces and what the session receipt attests
		// (SSOT, CWE-770).
		let granted_budgets = match (offer.requested_budgets, local.requested_budgets) {
			(Some(requested), Some(ceiling)) => Some(requested.min(ceiling).clamped()),
			_ => None,
		};

		Some(TransportAccept {
			mux: true,
			max_peer_initiated_streams: local.max_peer_initiated_streams,
			chunk_payload_size: local.chunk_payload_size,
			credit_unit: clamp_credit_unit(local.credit_unit),
			initial_stream_credit: local.initial_stream_credit,
			granted_budgets,
		})
	}

	/// Runs the accept path with an optional [`TransportAuthorizer`].
	///
	/// The path starts from [`TransportNegotiation::accept`], and
	/// [`MuxSettings::for_client`] enforces client consistency for an
	/// unsolicited or over-request grant.
	///
	/// # Budgets
	///
	/// When an authorizer is present, its grant replaces the local-config
	/// budget. The grant is still clamped to the componentwise minimum with
	/// the client's request before the accept and the receipt bind it.
	///
	/// # Errors
	///
	/// - [`NegotiationError::AuthorizationRefused`] -- the authorizer refused the offer.
	/// - [`NegotiationError::ChallengeWithoutBudgets`] -- the authorizer issued
	///   a challenge without budgets, so no receipt exists to carry it.
	pub(crate) async fn authorize(
		self,
		authorizer: Option<&dyn TransportAuthorizer>,
	) -> Result<Option<AuthorizedTransport>, NegotiationError> {
		let mut accept = match self.accept() {
			Some(accept) => accept,
			None => return Ok(None),
		};
		let (Some(authorizer), Some(offer)) = (authorizer, self.offer) else {
			let authorized = AuthorizedTransport { accept, challenge: None };
			return Ok(Some(authorized));
		};

		let grant = authorizer.authorize(offer).await?;
		// The grant takes the bounds of a local-config grant, the minimum with
		// the request and then the session cap, before it enters the
		// transcript and the receipt (SSOT, CWE-770). A grant beyond the
		// request would bind the client's countersignature to figures it
		// never asked for.
		let granted_budgets = match (offer.requested_budgets, grant.budgets) {
			(Some(requested), Some(granted)) => Some(granted.min(requested).clamped()),
			_ => None,
		};

		accept.granted_budgets = granted_budgets;

		let challenge = grant.challenge;
		if challenge.is_some() && accept.granted_budgets.is_none() {
			return Err(NegotiationError::ChallengeWithoutBudgets);
		}

		let authorized = AuthorizedTransport { accept, challenge };
		Ok(Some(authorized))
	}
}

/// Refusal verdict from a [`TransportAuthorizer`].
///
/// The refusal carries an application-defined code from the shared u32 code
/// space.
///
/// # Code space
///
/// - Application codes sit at or above
///   [`MUX_APPLICATION_CODE_FLOOR`](crate::transport::envelopes::MUX_APPLICATION_CODE_FLOOR).
/// - Codes below the floor are reserved for the protocol, such as [`SETTLEMENT_UNSUPPORTED_CODE`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthorizationRefusal {
	/// Application-defined refusal code.
	pub code: u32,
}

/// Grant verdict from a [`TransportAuthorizer`].
///
/// The grant carries the budgets awarded and an optional settlement
/// challenge, such as an unsigned transaction, an invoice, or other opaque
/// bytes. The server puts the challenge in the [`SessionReceipt`] body, so
/// both receipt signatures cover it.
///
/// # Fail closed
///
/// Receipts exist only for budget-bearing sessions, so a challenge without
/// budgets has no receipt to carry it. That combination aborts the
/// handshake.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AuthorizationGrant {
	/// Per-direction budgets granted. `None` grants an unmetered session.
	pub budgets: Option<MuxBudgets>,
	/// Opaque settlement challenge bound into the session receipt.
	/// TightBeam treats it as opaque bytes.
	pub challenge: Option<OctetString>,
}

impl From<Option<MuxBudgets>> for AuthorizationGrant {
	fn from(budgets: Option<MuxBudgets>) -> Self {
		Self { budgets, challenge: None }
	}
}

/// Server policy for session budget grants and receipt settlement.
///
/// The handshake awaits two hooks inline, in this order:
///
/// 1. [`authorize`](Self::authorize) runs after the client [`TransportOffer`]
///    and before the accept enters the transcript.
/// 2. [`settle`](Self::settle) runs after the client's countersigned receipt verifies.
///
/// # Deadline
///
/// On tokio runtimes the transport's handshake deadline bounds both hooks. A
/// hook still pending when the deadline elapses aborts the handshake with
/// [`DeadlineExceeded`](crate::transport::TransportFailure::DeadlineExceeded).
///
/// Runtimes without a timer (non-tokio) enforce no library deadline, so bound
/// external work in the hook. A slow hook stalls per-connection handshake
/// state and widens the window an unauthenticated peer can hold it.
///
/// # Grants
///
/// - `budgets: Some(_)` opens a metered session. The library still clamps the
///   grant to the componentwise minimum with the client's request before it
///   binds the accept and the receipt.
/// - `budgets: None` opens an unmetered session. A client that requested
///   budgets fails closed with
///   [`BudgetGrantWithheld`](NegotiationError::BudgetGrantWithheld). To deny
///   metering, return [`AuthorizationRefusal`] instead of an empty grant.
/// - A challenge without budgets fails closed with
///   [`ChallengeWithoutBudgets`](NegotiationError::ChallengeWithoutBudgets),
///   because no receipt exists to carry it.
///
/// # Without an authorizer
///
/// The server applies its local accept rule alone, which grants the
/// componentwise minimum of the request and the local budget ceiling. A
/// server with no ceiling grants no budgets.
pub trait TransportAuthorizer: MaybeSend + MaybeSync {
	/// Grant budgets and an optional settlement challenge for `offer`.
	///
	/// The hook inspects [`TransportOffer::requested_budgets`] and the opaque
	/// [`TransportOffer::authorization`] token, and it returns an
	/// [`AuthorizationGrant`] or an [`AuthorizationRefusal`]. The server
	/// Finished signature covers the grant.
	///
	/// # Errors
	///
	/// - [`AuthorizationRefusal`] -- aborts the handshake with its application code.
	fn authorize<'a>(
		&'a self,
		offer: &'a TransportOffer,
	) -> MaybeSendFuture<'a, Result<AuthorizationGrant, AuthorizationRefusal>>;

	/// Settle the countersigned receipt at the client's key exchange.
	///
	/// The handshake calls this hook with the receipt body and the client's
	/// ancillary response after the countersignature verifies. The session
	/// activates only on `Ok`.
	///
	/// # Default
	///
	/// A challenge-free receipt settles with `Ok`. An authorizer that issues
	/// a challenge without overriding this method refuses every settlement
	/// with [`SETTLEMENT_UNSUPPORTED_CODE`].
	///
	/// # Errors
	///
	/// - [`AuthorizationRefusal`] -- aborts the handshake with its application code.
	fn settle<'a>(
		&'a self,
		receipt: &'a SessionReceipt,
		_response: Option<&'a [u8]>,
	) -> MaybeSendFuture<'a, Result<(), AuthorizationRefusal>> {
		Box::pin(async move {
			if receipt.ancillary.is_some() {
				return Err(AuthorizationRefusal { code: SETTLEMENT_UNSUPPORTED_CODE });
			}

			Ok(())
		})
	}

	/// Issue the settlement challenge for an in-band epoch-renewal
	/// receipt, given the session's initial receipt body.
	///
	/// The epoch receipt inherits the initial budgets and credit unit under
	/// the credit-match invariant, so only the challenge may vary. The session
	/// then calls [`TransportAuthorizer::settle`] on the renewed receipt as it
	/// does at the handshake.
	///
	/// # Default
	///
	/// The default renewal is challenge-free. The epoch receipt carries no
	/// ancillary and settles with `Ok` under the default `settle`.
	///
	/// # Errors
	///
	/// - [`AuthorizationRefusal`] -- refuses the renewal with its application
	///   code, and the session falls back to the drain path.
	fn challenge_renewal<'a>(
		&'a self,
		_prior: &'a SessionReceipt,
	) -> MaybeSendFuture<'a, Result<Option<OctetString>, AuthorizationRefusal>> {
		Box::pin(async move { Ok(None) })
	}
}

/// Refusal code the default [`TransportAuthorizer::settle`] emits when a
/// challenge-bearing receipt reaches an authorizer that never implemented
/// settlement.
///
/// The code is protocol-reserved, because it sits below the application
/// code floor.
pub const SETTLEMENT_UNSUPPORTED_CODE: u32 = 1;

/// Transport verdict after the authorizer ran on the offer and the accept.
pub struct AuthorizedTransport {
	/// The transport accept sent to the client and bound into the
	/// transcript.
	pub accept: TransportAccept,
	/// Settlement challenge from the authorizer, carried in the session
	/// receipt body.
	pub challenge: Option<OctetString>,
}

/// The end of the negotiation this endpoint holds. The role decides the
/// direction each local and peer figure maps to.
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
#[derive(Clone, Copy)]
enum LocalRole {
	Client,
	Server,
}

#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
impl LocalRole {
	/// Returns `(send_budget, recv_budget)` for this role from the granted
	/// budgets.
	///
	/// An absent grant yields `(None, None)`, which is unmetered.
	fn budget_views(self, granted: Option<MuxBudgets>) -> (Option<u64>, Option<u64>) {
		let granted = match granted {
			Some(budgets) => budgets.clamped(),
			None => return (None, None),
		};

		match self {
			Self::Client => (Some(granted.client_to_server), Some(granted.server_to_client)),
			Self::Server => (Some(granted.server_to_client), Some(granted.client_to_server)),
		}
	}

	/// Builds the directional [`MuxSettings`] for this role from the clamped
	/// values both endpoints observed.
	///
	/// The role selects which advertisement is the local receive side and
	/// which is the peer receive side.
	fn mux_settings(self, offer: &TransportOffer, accept: &TransportAccept) -> MuxSettings {
		let (send_budget, recv_budget) = self.budget_views(accept.granted_budgets);

		let local_initiated_cap;
		let peer_initiated_cap;
		let send_chunk_size;
		let recv_chunk_size;
		let initial_send_credit;
		let initial_recv_credit;
		if matches!(self, Self::Client) {
			local_initiated_cap = accept.max_peer_initiated_streams;
			peer_initiated_cap = offer.max_peer_initiated_streams;
			send_chunk_size = accept.chunk_payload_size;
			recv_chunk_size = offer.chunk_payload_size;
			initial_send_credit = accept.initial_stream_credit;
			initial_recv_credit = offer.initial_stream_credit;
		} else {
			local_initiated_cap = offer.max_peer_initiated_streams;
			peer_initiated_cap = accept.max_peer_initiated_streams;
			send_chunk_size = offer.chunk_payload_size;
			recv_chunk_size = accept.chunk_payload_size;
			initial_send_credit = offer.initial_stream_credit;
			initial_recv_credit = accept.initial_stream_credit;
		}

		MuxSettings {
			local_initiated_cap: clamp_stream_cap(local_initiated_cap),
			peer_initiated_cap: clamp_stream_cap(peer_initiated_cap),
			send_chunk_size: clamp_chunk_size(send_chunk_size),
			recv_chunk_size: clamp_chunk_size(recv_chunk_size),
			credit_unit: clamp_credit_unit(accept.credit_unit),
			initial_send_credit: clamp_stream_credit(initial_send_credit),
			initial_recv_credit: clamp_stream_credit(initial_recv_credit),
			send_budget,
			recv_budget,
		}
	}
}

#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
impl MuxSettings {
	/// Client-side settings derived from the offer and the accept.
	///
	/// The client validates the server's accept against its own offer, then
	/// builds directional settings through the shared clamp choke points. The
	/// receipt countersigns the raw granted budgets, so the client refuses
	/// every divergence instead of repairing it by clamping.
	///
	/// # Errors
	///
	/// - [`NegotiationError::UnsolicitedTransportAccept`] -- the accept enables
	///   mux without a matching mux offer, or it grants budgets the client
	///   never requested.
	/// - [`NegotiationError::BudgetBeyondCap`] -- the grant exceeds
	///   [`MAX_MUX_SESSION_BUDGET`]. A conforming server never emits it, and
	///   clamping would attest figures the client never enforces.
	/// - [`NegotiationError::BudgetBeyondRequest`] -- the grant exceeds the
	///   request. A conforming server grants the componentwise minimum with the
	///   request, so the client refuses to countersign figures it never asked
	///   for.
	/// - [`NegotiationError::BudgetGrantWithheld`] -- the client requested
	///   budgets and the accept grants none. A budget request asks for an
	///   attested, spend-bounded session, and running unmetered would silently
	///   drop the receipt. A client that tolerates an unmetered session
	///   requests no budgets.
	pub(crate) fn for_client(
		offer: Option<&TransportOffer>,
		accept: Option<&TransportAccept>,
	) -> Result<Option<Self>, NegotiationError> {
		let accept = match accept {
			Some(accept) => accept,
			None => return Ok(None),
		};
		if !accept.mux {
			return Ok(None);
		}

		let offer = match offer {
			Some(offer) if offer.mux => offer,
			_ => return Err(NegotiationError::UnsolicitedTransportAccept),
		};
		if accept.granted_budgets.is_some() && offer.requested_budgets.is_none() {
			return Err(NegotiationError::UnsolicitedTransportAccept);
		}
		if accept.granted_budgets.is_some_and(|granted| granted != granted.clamped()) {
			return Err(NegotiationError::BudgetBeyondCap);
		}
		if let (Some(granted), Some(requested)) = (accept.granted_budgets, offer.requested_budgets) {
			if granted != granted.min(requested) {
				return Err(NegotiationError::BudgetBeyondRequest);
			}
		}
		if accept.granted_budgets.is_none() && offer.requested_budgets.is_some() {
			return Err(NegotiationError::BudgetGrantWithheld);
		}

		let settings = LocalRole::Client.mux_settings(offer, accept);
		Ok(Some(settings))
	}

	/// Server-side settings from the client's offer and the server's accept,
	/// clamped through the same choke points as [`Self::for_client`].
	pub(crate) fn for_server(offer: &TransportOffer, accept: &TransportAccept) -> Self {
		LocalRole::Server.mux_settings(offer, accept)
	}
}

/// Errors from security profile and transport negotiation.
#[derive(Debug, Clone, PartialEq, Eq, Errorizable)]
pub enum NegotiationError {
	/// The peer offer shares no profile with the local supported list.
	#[error("No mutually supported security profile")]
	NoMutualProfile,

	/// The offer contains no profiles.
	#[error("Security offer is empty")]
	EmptyOffer,

	/// No profile meets the configured minimum-strength policy.
	#[error("No profile meets the minimum-strength policy")]
	BelowStrengthFloor,

	/// The profile names an algorithm the local provider does not run.
	#[error("Security profile names an algorithm the provider does not run")]
	UnrunnableProfile,

	/// The offer exceeds the maximum accepted profile count.
	#[error("Security offer too large: {count} profiles exceeds cap of {max}")]
	OfferTooLarge { count: usize, max: usize },

	/// The peer accepted a transport capability that the client never
	/// offered.
	#[error("Peer accepted a transport capability that was never offered")]
	UnsolicitedTransportAccept,

	/// The transport authorizer refused the session.
	#[error("Transport authorization refused: code {code}")]
	AuthorizationRefused { code: u32 },

	/// The authorizer issued a settlement challenge without granting
	/// budgets, so no receipt exists to carry it.
	#[error("Settlement challenge issued without budget grant")]
	ChallengeWithoutBudgets,

	/// The peer granted budgets beyond [`MAX_MUX_SESSION_BUDGET`], and the
	/// client refuses the grant instead of clamping it.
	#[error("Granted budgets exceed the session budget cap")]
	BudgetBeyondCap,

	/// The peer granted budgets beyond the client's request, and the client
	/// refuses to countersign them.
	#[error("Granted budgets exceed the requested budgets")]
	BudgetBeyondRequest,

	/// The peer withheld budgets from a session that requested them, and the
	/// client refuses to run the session unmetered.
	#[error("Budget grant withheld for a budget-requesting session")]
	BudgetGrantWithheld,

	/// DER encoding or decoding failed.
	#[error("DER encoding error: {0}")]
	DerError(DerDecodeError),
}

impl From<AuthorizationRefusal> for NegotiationError {
	fn from(refusal: AuthorizationRefusal) -> Self {
		Self::AuthorizationRefused { code: refusal.code }
	}
}

impl From<DerDecodeError> for NegotiationError {
	fn from(e: DerDecodeError) -> Self {
		Self::DerError(e)
	}
}

/// A security profile that the provider `P` runs.
///
/// A peer's descriptor names algorithms, and `P` runs one fixed set of them.
/// A descriptor becomes a `RunnableProfile` only when it names exactly the
/// algorithms of `P`'s own profile. A handshake therefore signs and keys a
/// session only under the identity its provider runs (CWE-345).
pub struct RunnableProfile<P> {
	descriptor: SecurityProfileDesc,
	provider: PhantomData<fn() -> P>,
}

impl<P: CryptoProvider> RunnableProfile<P> {
	/// Returns the profile `P` runs.
	pub fn native() -> Self {
		let profile = <P::Profile as Default>::default();
		let descriptor = SecurityProfileDesc::from(&profile);
		Self { descriptor, provider: PhantomData }
	}

	/// The descriptor both endpoints negotiated.
	pub fn descriptor(&self) -> SecurityProfileDesc {
		self.descriptor
	}

	/// The strength a [`ProfileStrengthPolicy`] judges, read from the
	/// provider's cipher and digest types.
	pub fn strength(&self) -> ProfileStrength {
		ProfileStrength {
			descriptor: self.descriptor,
			aead_key_bytes: <P::AeadCipher as KeySizeUser>::key_size(),
			digest_bytes: <P::Digest as Digest>::output_size(),
		}
	}
}

impl<P: CryptoProvider> TryFrom<SecurityProfileDesc> for RunnableProfile<P> {
	type Error = NegotiationError;

	/// # Errors
	///
	/// - [`NegotiationError::UnrunnableProfile`] -- `descriptor` names an
	///   algorithm other than one of `P`'s.
	fn try_from(descriptor: SecurityProfileDesc) -> Result<Self, Self::Error> {
		let native = Self::native();
		if descriptor != native.descriptor {
			return Err(NegotiationError::UnrunnableProfile);
		}

		Ok(native)
	}
}

impl<P> Clone for RunnableProfile<P> {
	fn clone(&self) -> Self {
		*self
	}
}

impl<P> Copy for RunnableProfile<P> {}

impl<P> PartialEq for RunnableProfile<P> {
	fn eq(&self, other: &Self) -> bool {
		self.descriptor == other.descriptor
	}
}

impl<P> Eq for RunnableProfile<P> {}

impl<P> core::fmt::Debug for RunnableProfile<P> {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		f.debug_tuple("RunnableProfile").field(&self.descriptor).finish()
	}
}

/// The strength of a runnable profile, as a [`ProfileStrengthPolicy`]
/// judges it.
///
/// The sizes come from the provider's types, so a policy judges the
/// algorithms the session runs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct ProfileStrength {
	/// The negotiated descriptor.
	pub descriptor: SecurityProfileDesc,
	/// Key length in bytes of the provider's AEAD cipher.
	pub aead_key_bytes: usize,
	/// Output length in bytes of the provider's digest.
	pub digest_bytes: usize,
}

/// Minimum-strength filter a handshake endpoint applies to profiles.
///
/// The policy blocks downgrade (CWE-757), so an endpoint refuses a mutually
/// supported weak profile unless the policy admits it.
pub trait ProfileStrengthPolicy {
	/// Returns `true` when `strength` meets the policy floor.
	fn meets_floor(&self, strength: &ProfileStrength) -> bool;
}

/// Default strength floor.
///
/// # Requires
///
/// - The AEAD key size is at least 256 bits.
/// - The digest output is at least 256 bits.
#[derive(Debug, Default, Clone, Copy)]
pub struct DefaultStrengthFloor;

/// Minimum AEAD key and digest output length in bytes, 256 bits each.
const DEFAULT_FLOOR_BYTES: usize = 32;

impl ProfileStrengthPolicy for DefaultStrengthFloor {
	fn meets_floor(&self, strength: &ProfileStrength) -> bool {
		let aead_ok = strength.aead_key_bytes >= DEFAULT_FLOOR_BYTES;
		let digest_ok = strength.digest_bytes >= DEFAULT_FLOOR_BYTES;
		aead_ok && digest_ok
	}
}

/// The strength floor one handshake endpoint holds.
///
/// A server selects only a profile that meets its floor, and a client accepts
/// only such a profile, whether or not it sent an offer. Without an explicit
/// policy the floor is [`DefaultStrengthFloor`].
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
#[derive(Clone, Default)]
pub(crate) struct StrengthFloor(Option<Arc<dyn ProfileStrengthPolicy + Send + Sync>>);

#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
impl StrengthFloor {
	/// A floor that applies `policy` in place of [`DefaultStrengthFloor`].
	pub(crate) fn with_policy(policy: Arc<dyn ProfileStrengthPolicy + Send + Sync>) -> Self {
		Self(Some(policy))
	}

	/// The policy this floor applies.
	pub(crate) fn policy(&self) -> &dyn ProfileStrengthPolicy {
		match &self.0 {
			Some(policy) => policy.as_ref(),
			None => &DefaultStrengthFloor,
		}
	}

	/// Refuse `profile` when it falls below this floor.
	///
	/// # Errors
	///
	/// - [`NegotiationError::BelowStrengthFloor`] -- the policy refuses the profile.
	pub(crate) fn admit<P: CryptoProvider>(&self, profile: &RunnableProfile<P>) -> Result<(), NegotiationError> {
		if !self.policy().meets_floor(&profile.strength()) {
			return Err(NegotiationError::BelowStrengthFloor);
		}

		Ok(())
	}
}

/// Strength policy that admits every profile.
///
/// This policy is the explicit opt-out of the minimum-strength floor. Prefer
/// [`DefaultStrengthFloor`] except for compatibility deployments and
/// downgrade-attack tests.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoStrengthFloor;

impl ProfileStrengthPolicy for NoStrengthFloor {
	fn meets_floor(&self, _strength: &ProfileStrength) -> bool {
		true
	}
}

impl SecurityOffer {
	/// Select the first mutually supported profile in *local* preference order.
	///
	/// The scan walks `supported` in its configured order and picks the first
	/// profile the peer also offered. The peer ordering carries no weight, so
	/// a MITM that rewrites it cannot steer selection toward a weaker mutual
	/// profile (CWE-757).
	///
	/// # Errors
	///
	/// - [`NegotiationError::EmptyOffer`] -- the peer sent an empty offer.
	/// - [`NegotiationError::OfferTooLarge`] -- the offer exceeds [`MAX_OFFER_PROFILES`].
	/// - [`NegotiationError::NoMutualProfile`] -- the offer shares no profile with `supported`.
	pub(crate) fn select_profile(
		&self,
		supported: impl AsRef<[SecurityProfileDesc]>,
	) -> Result<SecurityProfileDesc, NegotiationError> {
		let supported = supported.as_ref();
		if self.profiles.is_empty() {
			return Err(NegotiationError::EmptyOffer);
		}
		if self.profiles.len() > MAX_OFFER_PROFILES {
			return Err(NegotiationError::OfferTooLarge { count: self.profiles.len(), max: MAX_OFFER_PROFILES });
		}

		for candidate in supported {
			if self.profiles.contains(candidate) {
				return Ok(*candidate);
			}
		}

		Err(NegotiationError::NoMutualProfile)
	}
}

// Exercises mux negotiation helpers when a transport flavor is enabled.
#[cfg(all(test, any(feature = "transport-cms", feature = "transport-ecies")))]
mod tests {
	use core::error::Error;

	use super::*;
	use crate::asn1::{AlgorithmIdentifier, DigestInfo};
	use crate::crypto::profiles::DefaultCryptoProvider;
	use crate::oids::{
		AES_128_WRAP, AES_192_WRAP, AES_256_GCM, AES_256_WRAP, CURVE_SECP256K1, HASH_SHA3_256,
		SIGNER_ECDSA_WITH_SHA3_512,
	};

	fn sample_profile(id: u8) -> SecurityProfileDesc {
		let key_wrap = match id {
			1 => Some(AES_128_WRAP),
			2 => Some(AES_256_WRAP),
			3 => Some(AES_192_WRAP),
			_ => None,
		};
		SecurityProfileDesc {
			digest: Some(HASH_SHA3_256),
			aead: Some(AES_256_GCM),
			signature: Some(SIGNER_ECDSA_WITH_SHA3_512),
			kdf: Some(HASH_SHA3_256),
			curve: Some(CURVE_SECP256K1),
			key_wrap,
		}
	}

	#[test]
	fn test_offer_single() {
		let profile = sample_profile(1);
		let offer = SecurityOffer::single(profile);
		assert_eq!(offer.profiles.len(), 1);
		assert_eq!(offer.profiles[0], profile);
	}

	/// Caps 1/1, chunk 1024, unit 1024: the drain reserve is 5 records
	/// priced at 1 credit each.
	fn reserve_settings() -> MuxSettings {
		let mut settings = MuxSettings::symmetric(1);
		settings.send_chunk_size = 1024;
		settings.credit_unit = 1024;
		settings
	}

	#[test]
	fn test_drain_reserve_covers_responses_cancels_goaway() {
		let settings = MuxSettings { local_initiated_cap: 3, peer_initiated_cap: 5, ..MuxSettings::symmetric(1) };
		assert_eq!(settings.drain_reserve_records(), 17);
	}

	#[test]
	fn test_send_budget_reserve_prices_records() {
		let mut settings = reserve_settings();
		assert_eq!(settings.send_budget_reserve(), 5);

		settings.credit_unit = 512;
		assert_eq!(settings.send_budget_reserve(), 10);
	}

	#[test]
	fn test_usable_send_budget_subtracts_reserve() {
		let mut settings = reserve_settings();
		assert_eq!(settings.usable_send_budget(), None);

		settings.send_budget = Some(10);
		assert_eq!(settings.usable_send_budget(), Some(5));

		settings.send_budget = Some(3);
		assert_eq!(settings.usable_send_budget(), Some(0));
	}

	#[test]
	fn test_select_first_mutual() -> Result<(), Box<dyn Error>> {
		let p1 = sample_profile(1);
		let p2 = sample_profile(2);
		let p3 = sample_profile(3);

		let offer = SecurityOffer::new(Vec::from([p1, p2, p3]));
		let supported = [p2, p3];

		let selected = offer.select_profile(supported)?;
		assert_eq!(selected, p2);

		Ok(())
	}

	#[test]
	fn test_select_follows_server_preference_not_client_order() -> Result<(), Box<dyn Error>> {
		let p1 = sample_profile(1);
		let p2 = sample_profile(2);

		// Client prefers p1, server prefers p2. Server preference must win
		// so a MITM reordering the offer cannot force the weaker profile.
		let offer = SecurityOffer::new(Vec::from([p1, p2]));
		let supported = [p2, p1];

		let selected = offer.select_profile(supported)?;
		assert_eq!(selected, p2);

		Ok(())
	}

	#[test]
	fn test_no_mutual_profile() {
		let p1 = sample_profile(1);
		let p2 = sample_profile(2);
		let p3 = sample_profile(3);

		let offer = SecurityOffer::new(Vec::from([p1, p2]));
		let supported = [p3];

		let result = offer.select_profile(supported);
		assert!(matches!(result, Err(NegotiationError::NoMutualProfile)));
	}

	#[test]
	fn test_oversized_offer_rejected() {
		let profile = sample_profile(1);
		let offer = SecurityOffer::new(vec![profile; MAX_OFFER_PROFILES + 1]);
		let supported = [profile];

		let result = offer.select_profile(supported);
		assert!(matches!(result, Err(NegotiationError::OfferTooLarge { count: 33, max: 32 })));
	}

	#[test]
	fn test_empty_offer() {
		let offer = SecurityOffer::new(Vec::new());
		let supported = [sample_profile(1)];
		let result = offer.select_profile(supported);
		assert!(matches!(result, Err(NegotiationError::EmptyOffer)));
	}

	fn disabled_offer(cap: u32) -> TransportOffer {
		TransportOffer { mux: false, ..TransportOffer::mux(cap) }
	}

	fn transport_negotiation<'a>(
		offer: Option<&'a TransportOffer>,
		local: Option<&'a TransportOffer>,
	) -> TransportNegotiation<'a> {
		TransportNegotiation { offer, local }
	}

	fn plain_accept(cap: u32) -> TransportAccept {
		TransportAccept {
			mux: true,
			max_peer_initiated_streams: cap,
			chunk_payload_size: DEFAULT_MUX_CHUNK_SIZE,
			credit_unit: DEFAULT_MUX_CREDIT_UNIT,
			initial_stream_credit: DEFAULT_MUX_STREAM_CREDIT,
			granted_budgets: None,
		}
	}

	fn require_client_mux(offer: &TransportOffer, accept: &TransportAccept) -> Result<MuxSettings, NegotiationError> {
		let settings = MuxSettings::for_client(Some(offer), Some(accept))?;
		settings.ok_or(NegotiationError::UnsolicitedTransportAccept)
	}

	#[test]
	fn test_accept_transport_activates_when_both_enable_mux() {
		let offer = TransportOffer::mux(8);
		let local = TransportOffer::mux(4);

		let accept = transport_negotiation(Some(&offer), Some(&local)).accept();
		assert!(matches!(
			accept,
			Some(TransportAccept { mux: true, max_peer_initiated_streams: 4, .. })
		));
	}

	#[test]
	fn test_accept_transport_absent_offer_declines() {
		let local = TransportOffer::mux(4);
		assert!(transport_negotiation(None, Some(&local)).accept().is_none());
	}

	#[test]
	fn test_accept_transport_absent_local_declines() {
		let offer = TransportOffer::mux(8);
		assert!(transport_negotiation(Some(&offer), None).accept().is_none());
	}

	#[test]
	fn test_accept_transport_disabled_offer_declines() {
		let disabled = disabled_offer(8);
		let local = TransportOffer::mux(4);
		let negotiation = transport_negotiation(Some(&disabled), Some(&local));

		let accepted = negotiation.accept();
		assert!(accepted.is_none());
	}

	#[test]
	fn test_accept_transport_disabled_local_declines() {
		let offer = TransportOffer::mux(8);
		let disabled = disabled_offer(4);
		let negotiation = transport_negotiation(Some(&offer), Some(&disabled));

		let accepted = negotiation.accept();
		assert!(accepted.is_none());
	}

	#[test]
	fn test_accept_transport_grants_min_of_request_and_ceiling() {
		let request = MuxBudgets { client_to_server: 100, server_to_client: 900 };
		let ceiling = MuxBudgets { client_to_server: 500, server_to_client: 300 };
		let offer = TransportOffer::mux(8).with_budgets(request);
		let local = TransportOffer::mux(4).with_budgets(ceiling);

		let accept = transport_negotiation(Some(&offer), Some(&local)).accept();
		let granted = accept.and_then(|accept| accept.granted_budgets);
		assert_eq!(granted, Some(MuxBudgets { client_to_server: 100, server_to_client: 300 }));
	}

	#[test]
	fn test_accept_transport_grants_nothing_unrequested() {
		let ceiling = MuxBudgets { client_to_server: 500, server_to_client: 300 };
		let offer = TransportOffer::mux(8);
		let local = TransportOffer::mux(4).with_budgets(ceiling);

		let accept = transport_negotiation(Some(&offer), Some(&local)).accept();
		let granted = accept.and_then(|accept| accept.granted_budgets);
		assert_eq!(granted, None);
	}

	#[test]
	fn test_accept_transport_without_ceiling_grants_nothing() {
		let request = MuxBudgets { client_to_server: 100, server_to_client: 900 };
		let offer = TransportOffer::mux(8).with_budgets(request);
		let local = TransportOffer::mux(4);

		let accept = transport_negotiation(Some(&offer), Some(&local)).accept();
		let granted = accept.and_then(|accept| accept.granted_budgets);
		assert_eq!(granted, None);
	}

	struct FixedAuthorizer {
		verdict: Result<Option<MuxBudgets>, AuthorizationRefusal>,
		challenge: Option<OctetString>,
	}

	impl FixedAuthorizer {
		fn budgets(verdict: Result<Option<MuxBudgets>, AuthorizationRefusal>) -> Self {
			Self { verdict, challenge: None }
		}
	}

	impl TransportAuthorizer for FixedAuthorizer {
		fn authorize<'a>(
			&'a self,
			_offer: &'a TransportOffer,
		) -> MaybeSendFuture<'a, Result<AuthorizationGrant, AuthorizationRefusal>> {
			Box::pin(async move {
				let budgets = self.verdict?;
				Ok(AuthorizationGrant { budgets, challenge: self.challenge.to_owned() })
			})
		}
	}

	#[tokio::test]
	async fn test_authorize_transport_defaults_to_local_config() -> Result<(), NegotiationError> {
		let request = MuxBudgets { client_to_server: 100, server_to_client: 900 };
		let ceiling = MuxBudgets { client_to_server: 500, server_to_client: 300 };
		let offer = TransportOffer::mux(8).with_budgets(request);
		let local = TransportOffer::mux(4).with_budgets(ceiling);

		let negotiation = transport_negotiation(Some(&offer), Some(&local));
		let accept = negotiation.authorize(None).await?;
		let granted = accept.and_then(|authorized| authorized.accept.granted_budgets);
		assert_eq!(granted, Some(MuxBudgets { client_to_server: 100, server_to_client: 300 }));

		Ok(())
	}

	#[tokio::test]
	async fn test_authorize_transport_verdict_replaces_local_grant() -> Result<(), NegotiationError> {
		let request = MuxBudgets { client_to_server: 100, server_to_client: 900 };
		let verdict = MuxBudgets { client_to_server: 40, server_to_client: 60 };
		let offer = TransportOffer::mux(8).with_budgets(request);
		let local = TransportOffer::mux(4).with_budgets(request);
		let authorizer = FixedAuthorizer::budgets(Ok(Some(verdict)));

		let negotiation = transport_negotiation(Some(&offer), Some(&local));
		let accept = negotiation.authorize(Some(&authorizer)).await?;
		let granted = accept.and_then(|authorized| authorized.accept.granted_budgets);
		assert_eq!(granted, Some(verdict));

		Ok(())
	}

	#[tokio::test]
	async fn test_authorize_transport_grant_bounded_by_request() -> Result<(), NegotiationError> {
		let request = MuxBudgets { client_to_server: 100, server_to_client: 900 };
		let verdict = MuxBudgets { client_to_server: 250, server_to_client: 60 };
		let offer = TransportOffer::mux(8).with_budgets(request);
		let local = TransportOffer::mux(4).with_budgets(request);
		let authorizer = FixedAuthorizer::budgets(Ok(Some(verdict)));

		let negotiation = transport_negotiation(Some(&offer), Some(&local));
		let accept = negotiation.authorize(Some(&authorizer)).await?;
		let granted = accept.and_then(|authorized| authorized.accept.granted_budgets);
		assert_eq!(granted, Some(MuxBudgets { client_to_server: 100, server_to_client: 60 }));

		Ok(())
	}

	#[tokio::test]
	async fn test_authorize_transport_refusal_carries_code() {
		let request = MuxBudgets { client_to_server: 100, server_to_client: 900 };
		let offer = TransportOffer::mux(8).with_budgets(request);
		let local = TransportOffer::mux(4);
		let authorizer = FixedAuthorizer::budgets(Err(AuthorizationRefusal { code: 7 }));

		let negotiation = transport_negotiation(Some(&offer), Some(&local));
		let result = negotiation.authorize(Some(&authorizer)).await;
		assert!(matches!(result, Err(NegotiationError::AuthorizationRefused { code: 7 })));
	}

	#[tokio::test]
	async fn test_authorize_transport_masks_unsolicited_grant() -> Result<(), NegotiationError> {
		let verdict = MuxBudgets { client_to_server: 40, server_to_client: 60 };
		let offer = TransportOffer::mux(8);
		let local = TransportOffer::mux(4);
		let authorizer = FixedAuthorizer::budgets(Ok(Some(verdict)));

		let negotiation = transport_negotiation(Some(&offer), Some(&local));
		let accept = negotiation.authorize(Some(&authorizer)).await?;
		let granted = accept.and_then(|authorized| authorized.accept.granted_budgets);
		assert_eq!(granted, None);

		Ok(())
	}

	#[tokio::test]
	async fn test_authorize_transport_inactive_mux_skips_authorizer() -> Result<(), NegotiationError> {
		let offer = TransportOffer::mux(8);
		let authorizer = FixedAuthorizer::budgets(Err(AuthorizationRefusal { code: 7 }));

		let negotiation = transport_negotiation(Some(&offer), None);
		let accept = negotiation.authorize(Some(&authorizer)).await?;
		assert!(accept.is_none());

		Ok(())
	}

	#[tokio::test]
	async fn test_authorize_transport_carries_challenge_with_budgets() -> Result<(), NegotiationError> {
		let request = MuxBudgets { client_to_server: 100, server_to_client: 900 };
		let offer = TransportOffer::mux(8).with_budgets(request);
		let local = TransportOffer::mux(4);
		let challenge = OctetString::new(b"invoice".as_slice()).map_err(NegotiationError::DerError)?;
		let authorizer = FixedAuthorizer { verdict: Ok(Some(request)), challenge: Some(challenge.to_owned()) };

		let negotiation = transport_negotiation(Some(&offer), Some(&local));
		let authorized = negotiation.authorize(Some(&authorizer)).await?;
		let challenge_out = authorized.and_then(|authorized| authorized.challenge);
		assert_eq!(challenge_out, Some(challenge));

		Ok(())
	}

	#[tokio::test]
	async fn test_authorize_transport_challenge_without_budgets_fails_closed() -> Result<(), NegotiationError> {
		let offer = TransportOffer::mux(8);
		let local = TransportOffer::mux(4);
		let challenge = OctetString::new(b"invoice".as_slice()).map_err(NegotiationError::DerError)?;
		let authorizer = FixedAuthorizer { verdict: Ok(None), challenge: Some(challenge) };

		let negotiation = transport_negotiation(Some(&offer), Some(&local));
		let result = negotiation.authorize(Some(&authorizer)).await;
		assert!(matches!(result, Err(NegotiationError::ChallengeWithoutBudgets)));

		Ok(())
	}

	fn settle_receipt(ancillary: Option<OctetString>) -> Result<SessionReceipt, DerDecodeError> {
		let algorithm = AlgorithmIdentifier { oid: HASH_SHA3_256, parameters: None };
		Ok(SessionReceipt {
			transcript_hash: DigestInfo { algorithm, digest: OctetString::new([0u8; 32])? },
			budgets: MuxBudgets { client_to_server: 1, server_to_client: 1 },
			credit_unit: 1024,
			ancillary,
		})
	}

	#[tokio::test]
	async fn test_default_settle_accepts_challenge_free_receipt() -> Result<(), DerDecodeError> {
		let authorizer = FixedAuthorizer::budgets(Ok(None));
		let receipt = settle_receipt(None)?;
		assert_eq!(authorizer.settle(&receipt, None).await, Ok(()));
		Ok(())
	}

	#[tokio::test]
	async fn test_default_settle_refuses_challenge_bearing_receipt() -> Result<(), DerDecodeError> {
		let authorizer = FixedAuthorizer::budgets(Ok(None));
		let receipt = settle_receipt(Some(OctetString::new(b"invoice".as_slice())?))?;
		let settled = authorizer.settle(&receipt, None).await;
		assert_eq!(settled, Err(AuthorizationRefusal { code: SETTLEMENT_UNSUPPORTED_CODE }));
		Ok(())
	}

	#[test]
	fn test_mux_settings_directional_caps() -> Result<(), NegotiationError> {
		let offer = TransportOffer::mux(8);
		let accept = plain_accept(4);

		let client = require_client_mux(&offer, &accept)?;
		assert_eq!(client.local_initiated_cap, 4);
		assert_eq!(client.peer_initiated_cap, 8);

		let server = MuxSettings::for_server(&offer, &accept);
		assert_eq!(server.local_initiated_cap, 8);
		assert_eq!(server.peer_initiated_cap, 4);

		Ok(())
	}

	#[test]
	fn test_mux_settings_directional_chunk_and_credit_views() -> Result<(), NegotiationError> {
		let offer = TransportOffer::mux(8)
			.with_chunk_payload_size(8 * 1024)
			.with_credit_unit(512)
			.with_initial_stream_credit(16);
		let accept = TransportAccept {
			chunk_payload_size: 32 * 1024,
			credit_unit: 2048,
			initial_stream_credit: 32,
			..plain_accept(4)
		};

		let client = require_client_mux(&offer, &accept)?;
		assert_eq!(client.send_chunk_size, 32 * 1024);
		assert_eq!(client.recv_chunk_size, 8 * 1024);
		assert_eq!(client.credit_unit, 2048);
		assert_eq!(client.initial_send_credit, 32);
		assert_eq!(client.initial_recv_credit, 16);

		let server = MuxSettings::for_server(&offer, &accept);
		assert_eq!(server.send_chunk_size, 8 * 1024);
		assert_eq!(server.recv_chunk_size, 32 * 1024);
		assert_eq!(server.credit_unit, 2048);
		assert_eq!(server.initial_send_credit, 16);
		assert_eq!(server.initial_recv_credit, 32);

		Ok(())
	}

	#[test]
	fn test_mux_settings_budget_views_by_role() -> Result<(), NegotiationError> {
		let budgets = MuxBudgets { client_to_server: 100, server_to_client: 300 };
		let offer = TransportOffer::mux(8).with_budgets(budgets);
		let accept = TransportAccept { granted_budgets: Some(budgets), ..plain_accept(4) };

		let client = require_client_mux(&offer, &accept)?;
		assert_eq!(client.send_budget, Some(100));
		assert_eq!(client.recv_budget, Some(300));

		let server = MuxSettings::for_server(&offer, &accept);
		assert_eq!(server.send_budget, Some(300));
		assert_eq!(server.recv_budget, Some(100));

		Ok(())
	}

	#[test]
	fn test_mux_settings_zero_budget_is_metered() -> Result<(), NegotiationError> {
		let budgets = MuxBudgets { client_to_server: 0, server_to_client: 0 };
		let offer = TransportOffer::mux(8).with_budgets(budgets);
		let accept = TransportAccept { granted_budgets: Some(budgets), ..plain_accept(4) };

		let client = require_client_mux(&offer, &accept)?;
		assert_eq!(client.send_budget, Some(0));
		assert_eq!(client.recv_budget, Some(0));

		Ok(())
	}

	#[test]
	fn test_mux_settings_clamp_peer_advertised_caps() -> Result<(), NegotiationError> {
		let offer = TransportOffer::mux(u32::MAX);
		let accept = plain_accept(u32::MAX);

		let client = require_client_mux(&offer, &accept)?;
		assert_eq!(client.local_initiated_cap, MAX_MUX_STREAM_CAP);
		assert_eq!(client.peer_initiated_cap, MAX_MUX_STREAM_CAP);

		let server = MuxSettings::for_server(&offer, &accept);
		assert_eq!(server.local_initiated_cap, MAX_MUX_STREAM_CAP);
		assert_eq!(server.peer_initiated_cap, MAX_MUX_STREAM_CAP);

		Ok(())
	}

	#[test]
	fn test_mux_settings_stream_credit_floor() -> Result<(), NegotiationError> {
		let offer = TransportOffer::mux(8).with_initial_stream_credit(0);
		let accept = TransportAccept { initial_stream_credit: 0, ..plain_accept(4) };

		let client = require_client_mux(&offer, &accept)?;
		assert_eq!(client.initial_send_credit, 1);
		assert_eq!(client.initial_recv_credit, 1);

		Ok(())
	}

	#[test]
	fn test_mux_settings_clamp_chunk_credit_and_budget() -> Result<(), NegotiationError> {
		let at_cap = MuxBudgets {
			client_to_server: MAX_MUX_SESSION_BUDGET,
			server_to_client: MAX_MUX_SESSION_BUDGET,
		};
		let offer = TransportOffer::mux(8)
			.with_chunk_payload_size(1)
			.with_credit_unit(0)
			.with_initial_stream_credit(u64::MAX)
			.with_budgets(at_cap);
		let accept = TransportAccept {
			chunk_payload_size: u32::MAX,
			credit_unit: 0,
			initial_stream_credit: u64::MAX,
			granted_budgets: Some(at_cap),
			..plain_accept(4)
		};

		let client = require_client_mux(&offer, &accept)?;
		assert_eq!(client.send_chunk_size, MAX_MUX_CHUNK_SIZE);
		assert_eq!(client.recv_chunk_size, MIN_MUX_CHUNK_SIZE);
		assert_eq!(client.credit_unit, 1);
		assert_eq!(client.initial_send_credit, MAX_MUX_STREAM_CREDIT);
		assert_eq!(client.initial_recv_credit, MAX_MUX_STREAM_CREDIT);
		assert_eq!(client.send_budget, Some(MAX_MUX_SESSION_BUDGET));
		assert_eq!(client.recv_budget, Some(MAX_MUX_SESSION_BUDGET));

		Ok(())
	}

	#[test]
	fn test_symmetric_settings_clamp_cap() {
		let settings = MuxSettings::symmetric(u32::MAX);
		assert_eq!(settings.local_initiated_cap, MAX_MUX_STREAM_CAP);
		assert_eq!(settings.peer_initiated_cap, MAX_MUX_STREAM_CAP);
	}

	#[test]
	fn test_symmetric_settings_default_flow_control_unmetered() {
		let settings = MuxSettings::symmetric(8);
		assert_eq!(settings.send_chunk_size, DEFAULT_MUX_CHUNK_SIZE);
		assert_eq!(settings.recv_chunk_size, DEFAULT_MUX_CHUNK_SIZE);
		assert_eq!(settings.credit_unit, DEFAULT_MUX_CREDIT_UNIT);
		assert_eq!(settings.initial_send_credit, DEFAULT_MUX_STREAM_CREDIT);
		assert_eq!(settings.initial_recv_credit, DEFAULT_MUX_STREAM_CREDIT);
		assert_eq!(settings.send_budget, None);
		assert_eq!(settings.recv_budget, None);
	}

	#[test]
	fn test_unsolicited_transport_accept_fails_closed() {
		let accept = plain_accept(4);

		let result = MuxSettings::for_client(None, Some(&accept));
		assert!(matches!(result, Err(NegotiationError::UnsolicitedTransportAccept)));

		let disabled = disabled_offer(8);
		let result = MuxSettings::for_client(Some(&disabled), Some(&accept));
		assert!(matches!(result, Err(NegotiationError::UnsolicitedTransportAccept)));
	}

	#[test]
	fn test_unsolicited_granted_budget_fails_closed() {
		let offer = TransportOffer::mux(8);
		let budgets = MuxBudgets { client_to_server: 100, server_to_client: 300 };
		let accept = TransportAccept { granted_budgets: Some(budgets), ..plain_accept(4) };

		let result = MuxSettings::for_client(Some(&offer), Some(&accept));
		assert!(matches!(result, Err(NegotiationError::UnsolicitedTransportAccept)));
	}

	#[test]
	fn test_over_cap_granted_budget_fails_closed() {
		let over_cap = MuxBudgets { client_to_server: MAX_MUX_SESSION_BUDGET + 1, server_to_client: 1 };
		let offer = TransportOffer::mux(8).with_budgets(over_cap);
		let accept = TransportAccept { granted_budgets: Some(over_cap), ..plain_accept(4) };

		let result = MuxSettings::for_client(Some(&offer), Some(&accept));
		assert!(matches!(result, Err(NegotiationError::BudgetBeyondCap)));
	}

	#[test]
	fn test_over_request_granted_budget_fails_closed() {
		let request = MuxBudgets { client_to_server: 100, server_to_client: 300 };
		let over_request = MuxBudgets { client_to_server: 100, server_to_client: 301 };
		let offer = TransportOffer::mux(8).with_budgets(request);
		let accept = TransportAccept { granted_budgets: Some(over_request), ..plain_accept(4) };

		let result = MuxSettings::for_client(Some(&offer), Some(&accept));
		assert!(matches!(result, Err(NegotiationError::BudgetBeyondRequest)));
	}

	#[test]
	fn test_withheld_budget_grant_fails_closed() {
		let request = MuxBudgets { client_to_server: 100, server_to_client: 300 };
		let offer = TransportOffer::mux(8).with_budgets(request);
		let accept = plain_accept(4);

		let result = MuxSettings::for_client(Some(&offer), Some(&accept));
		assert!(matches!(result, Err(NegotiationError::BudgetGrantWithheld)));
	}

	#[test]
	fn test_no_accept_means_mux_inactive() -> Result<(), NegotiationError> {
		let offer = TransportOffer::mux(8);
		assert!(MuxSettings::for_client(Some(&offer), None)?.is_none());
		assert!(MuxSettings::for_client(None, None)?.is_none());

		let declined = TransportAccept { mux: false, ..plain_accept(0) };
		assert!(MuxSettings::for_client(Some(&offer), Some(&declined))?.is_none());
		Ok(())
	}

	#[cfg(feature = "aead")]
	#[test]
	fn test_select_profile_follows_server_aead_preference() -> Result<(), Box<dyn Error>> {
		use crate::oids::{
			AES_128_GCM, AES_128_WRAP, AES_256_GCM, AES_256_WRAP, CURVE_SECP256K1, HASH_SHA256,
			SIGNER_ECDSA_WITH_SHA256,
		};

		let aes128_gcm = SecurityProfileDesc {
			digest: Some(HASH_SHA256),
			aead: Some(AES_128_GCM),
			signature: Some(SIGNER_ECDSA_WITH_SHA256),
			kdf: Some(HASH_SHA256),
			curve: Some(CURVE_SECP256K1),
			key_wrap: Some(AES_128_WRAP),
		};
		let aes256_gcm = SecurityProfileDesc {
			digest: Some(HASH_SHA256),
			aead: Some(AES_256_GCM),
			signature: Some(SIGNER_ECDSA_WITH_SHA256),
			kdf: Some(HASH_SHA256),
			curve: Some(CURVE_SECP256K1),
			key_wrap: Some(AES_256_WRAP),
		};

		let selected_aead = |client: &[SecurityProfileDesc], server: &[SecurityProfileDesc]| {
			SecurityOffer::new(client.to_vec())
				.select_profile(server)
				.map(|selected| selected.aead)
		};

		assert_eq!(
			selected_aead(&[aes128_gcm, aes256_gcm], &[aes256_gcm, aes128_gcm])?,
			Some(AES_256_GCM)
		);
		assert_eq!(
			selected_aead(&[aes256_gcm, aes128_gcm], &[aes256_gcm, aes128_gcm])?,
			Some(AES_256_GCM)
		);
		assert_eq!(
			selected_aead(&[aes256_gcm, aes128_gcm], &[aes128_gcm, aes256_gcm])?,
			Some(AES_128_GCM)
		);
		assert_eq!(selected_aead(&[aes128_gcm, aes256_gcm], &[aes256_gcm])?, Some(AES_256_GCM));
		Ok(())
	}

	#[test]
	fn a_descriptor_that_names_a_foreign_algorithm_is_not_runnable() {
		let native = RunnableProfile::<DefaultCryptoProvider>::native().descriptor();
		let foreign = SecurityProfileDesc { digest: Some(crate::oids::HASH_SHA3_512), ..native };

		let result = RunnableProfile::<DefaultCryptoProvider>::try_from(foreign);

		assert!(matches!(result, Err(NegotiationError::UnrunnableProfile)));
	}

	#[test]
	fn a_runnable_profile_reports_the_provider_key_and_digest_sizes() {
		let strength = RunnableProfile::<DefaultCryptoProvider>::native().strength();
		assert_eq!(strength.aead_key_bytes, 32);
		assert_eq!(strength.digest_bytes, 32);
	}

	#[test]
	fn the_default_floor_refuses_a_128_bit_aead_key() {
		let strength = RunnableProfile::<DefaultCryptoProvider>::native().strength();
		let weak = ProfileStrength { aead_key_bytes: 16, ..strength };
		assert!(DefaultStrengthFloor.meets_floor(&strength));
		assert!(!DefaultStrengthFloor.meets_floor(&weak));
	}
}
