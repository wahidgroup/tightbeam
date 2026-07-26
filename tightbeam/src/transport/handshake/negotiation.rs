//! Security profile and transport negotiation for TightBeam handshakes.
//!
//! Wire structures (offer / accept) carry algorithm and mux capability
//! without instantiating concrete crypto during negotiation. Server and
//! client helpers derive clamped [`MuxSettings`] and consult optional
//! [`TransportAuthorizer`] / strength policy hooks.
//!
//! Profile selection is in *local* preference order so MITM reordering of
//! the peer offer cannot steer the choice (CWE-757).

#[cfg(not(feature = "std"))]
extern crate alloc;

use crate::constants::{
	DEFAULT_MUX_CHUNK_SIZE, DEFAULT_MUX_CREDIT_UNIT, DEFAULT_MUX_STREAM_CREDIT, MAX_MUX_STREAM_CAP,
};
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
use crate::constants::{MAX_MUX_CHUNK_SIZE, MAX_MUX_SESSION_BUDGET, MAX_MUX_STREAM_CREDIT, MIN_MUX_CHUNK_SIZE};
use crate::crypto::profiles::SecurityProfileDesc;
use crate::der::asn1::{ObjectIdentifier, OctetString};
use crate::der::Error as DerDecodeError;
use crate::der::Sequence;
use crate::transport::handshake::receipt::SessionReceipt;
use crate::utils::marker::{MaybeSend, MaybeSendFuture, MaybeSync};
use crate::Beamable;

#[cfg(not(feature = "std"))]
use alloc::boxed::Box;
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
#[cfg(feature = "std")]
use std::vec::Vec;

#[cfg(feature = "derive")]
use crate::Errorizable;

/// Maximum number of profiles accepted in a [`SecurityOffer`].
///
/// Bounds the pre-authentication O(offer x supported) negotiation scan
/// against offer-flood DoS (CWE-770).
pub const MAX_OFFER_PROFILES: usize = 32;

/// Client security-profile offer on the wire (DER).
///
/// Advertises algorithm combinations the client supports. Preference
/// order is first-most-preferred, but the server selects in *its* local
/// order (peer offer ordering carries no weight).
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "derive", derive(Beamable, Sequence))]
pub struct SecurityOffer {
	/// Ordered list of security profile descriptors (preference: first is most preferred).
	pub profiles: Vec<SecurityProfileDesc>,
}

impl SecurityOffer {
	/// Preferential order: first profile is most preferred.
	pub fn new(profiles: Vec<SecurityProfileDesc>) -> Self {
		Self { profiles }
	}

	/// One-profile offer; same wire shape as a singleton list.
	pub fn single(profile: SecurityProfileDesc) -> Self {
		Self { profiles: Vec::from([profile]) }
	}
}

/// Server security-profile accept on the wire (DER).
///
/// Carries the profile selected from the client's [`SecurityOffer`]
/// under local preference and any [`ProfileStrengthPolicy`].
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "derive", derive(Beamable, Sequence))]
pub struct SecurityAccept {
	/// The selected security profile descriptor.
	pub profile: SecurityProfileDesc,
}

impl SecurityAccept {
	/// Profile the server selected from the peer offer.
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
/// Fixed per key epoch; only shrinks inside an epoch. Value semantics
/// (free, fiat, or other) live outside the protocol.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "derive", derive(Beamable, Sequence))]
pub struct MuxBudgets {
	/// Credits spendable on client-to-server data chunks.
	pub client_to_server: u64,
	/// Credits spendable on server-to-client data chunks.
	pub server_to_client: u64,
}

impl MuxBudgets {
	/// Componentwise minimum: the grant a server derives from a request
	/// under its local ceiling.
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

/// Client transport capability offer (multiplexing) on the wire.
///
/// Bound into the handshake transcript with the client's opening message.
///
/// # Directionality
///
/// ([RFC 9113 § 5.1.2](https://datatracker.ietf.org/doc/html/rfc9113#section-5.1.2))
/// Each field advertises what the *sender of this struct* will receive:
/// peer-initiated stream cap, inbound chunk size, inbound stream credit.
///
/// # Client to server only
///
/// - `requested_budgets` - metering request (`None` = unmetered).
/// - `authorization` - opaque token for [`TransportAuthorizer`] (never
///   parsed by TightBeam).
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "derive", derive(Beamable, Sequence))]
pub struct TransportOffer {
	/// Sender supports stream multiplexing.
	pub mux: bool,
	/// Concurrent streams the peer may initiate toward the sender.
	pub max_peer_initiated_streams: u32,
	/// Largest chunk payload the sender of this struct accepts inbound.
	/// Clamped to `MIN_MUX_CHUNK_SIZE..=MAX_MUX_CHUNK_SIZE`. Chunking has
	/// no opt-out value.
	pub chunk_payload_size: u32,
	/// Bytes per session-budget credit proposed by the client. The
	/// accepted value wins.
	pub credit_unit: u32,
	/// Initial per-stream chunk allowance the sender of this struct
	/// grants to inbound streams. Clamped to [`MAX_MUX_STREAM_CREDIT`].
	pub initial_stream_credit: u64,
	/// Per-direction session budgets the client requests. Absent means
	/// an unmetered session (flow control only).
	#[asn1(optional = "true")]
	pub requested_budgets: Option<MuxBudgets>,
	/// Opaque settlement token, transcript-bound, never parsed by
	/// TightBeam. Consumed by the server's `TransportAuthorizer`.
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

	/// Request per-direction session budgets for the session.
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

	/// Advertise the inbound chunk payload ceiling on the wire.
	#[must_use]
	pub fn with_chunk_payload_size(mut self, size: u32) -> Self {
		self.chunk_payload_size = size;
		self
	}

	/// Propose the bytes-per-credit unit; the accept value wins.
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

/// Server transport capability accept (multiplexing) on the wire.
///
/// Bound into the handshake transcript with the server's response.
/// Same directional shape as [`TransportOffer`]: the server advertises
/// what it will *receive*.
///
/// # Additionally
///
/// - `credit_unit` - wins for both directions.
/// - `granted_budgets` - metered terms (may be lower than requested per
///   direction; absent = unmetered).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "derive", derive(Beamable, Sequence))]
pub struct TransportAccept {
	/// Sender supports stream multiplexing.
	pub mux: bool,
	/// Concurrent streams the peer may initiate toward the sender.
	pub max_peer_initiated_streams: u32,
	/// Largest chunk payload the server accepts inbound.
	pub chunk_payload_size: u32,
	/// Bytes per session-budget credit. This value wins for both
	/// directions.
	pub credit_unit: u32,
	/// Initial per-stream chunk allowance the server grants to inbound
	/// streams.
	pub initial_stream_credit: u64,
	/// Per-direction budgets granted for the epoch. Absent means the
	/// session is unmetered.
	#[asn1(optional = "true")]
	pub granted_budgets: Option<MuxBudgets>,
}

/// Negotiated multiplexing settings for one connection endpoint.
///
/// Derived from the same clamped wire offer/accept both sides observed.
///
/// # Directionality
///
/// ([RFC 9113 § 5.1.2](https://datatracker.ietf.org/doc/html/rfc9113#section-5.1.2))
/// Caps, chunk sizes, and stream credit are directional: each endpoint
/// enforces what it advertised and respects what its peer advertised.
/// There is no symmetric min-collapse.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MuxSettings {
	/// Concurrent streams this endpoint may initiate (peer-advertised).
	pub local_initiated_cap: u32,
	/// Concurrent streams the peer may initiate.
	pub peer_initiated_cap: u32,
	/// Largest chunk payload this endpoint may send (peer-advertised
	/// receive size).
	pub send_chunk_size: u32,
	/// Largest chunk payload accepted inbound (locally advertised).
	pub recv_chunk_size: u32,
	/// Bytes per session-budget credit, both directions (accepted value).
	pub credit_unit: u32,
	/// Initial chunk allowance on each stream this endpoint initiates
	/// or answers toward the peer (peer-advertised).
	pub initial_send_credit: u64,
	/// Initial chunk allowance granted to each inbound stream (locally
	/// advertised).
	pub initial_recv_credit: u64,
	/// Credits spendable on outbound data this epoch. `None` = unmetered.
	pub send_budget: Option<u64>,
	/// Credits the peer may spend on inbound data this epoch, enforced
	/// locally. `None` = unmetered.
	pub recv_budget: Option<u64>,
}

impl MuxSettings {
	/// Equal caps both ways with default chunking and credit, for links
	/// without handshake negotiation (cleartext multiplexing).
	///
	/// # Budgets
	///
	/// Always unmetered. Without an encrypted session there is no epoch
	/// to renew, so a spendable bound would be unrecoverable.
	///
	/// # Contract
	///
	/// Both endpoints MUST configure the same `cap` or enforcement
	/// diverges. Clamped to [`MAX_MUX_STREAM_CAP`].
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
}

/// Clamp a wire-advertised concurrent-stream cap to
/// [`MAX_MUX_STREAM_CAP`] (CWE-770). Applied identically by both endpoints
/// to the same wire value, so directional views stay consistent.
fn clamp_stream_cap(cap: u32) -> u32 {
	cap.min(MAX_MUX_STREAM_CAP)
}

/// Clamp a wire-advertised chunk payload size into
/// `MIN_MUX_CHUNK_SIZE..=MAX_MUX_CHUNK_SIZE`. The floor stops tiny
/// advertisements from amplifying record consumption (CWE-770). There is
/// no opt-out value because chunking is the only send path.
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
fn clamp_chunk_size(size: u32) -> u32 {
	size.clamp(MIN_MUX_CHUNK_SIZE, MAX_MUX_CHUNK_SIZE)
}

/// Clamp a wire-advertised credit unit to at least one byte so debit
/// arithmetic never divides by zero.
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
fn clamp_credit_unit(unit: u32) -> u32 {
	unit.max(1)
}

/// Clamp a wire-advertised initial stream credit window into
/// `1..=MAX_MUX_STREAM_CREDIT`. The ceiling bounds receive memory
/// (CWE-770). The floor of one chunk keeps every stream startable, since
/// credit grants only flow once a first chunk has arrived.
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
fn clamp_stream_credit(credit: u64) -> u64 {
	credit.clamp(1, MAX_MUX_STREAM_CREDIT)
}

/// Server-side accept rule before any authorizer runs.
///
/// Multiplexing activates only when the peer offered it and it is
/// locally enabled. Missing offer or local config yields no accept, so
/// both endpoints share the same activation decision.
///
/// The local [`TransportOffer`] is server configuration: receive-side
/// values are advertised back; `requested_budgets` is the grant ceiling
/// (componentwise minimum with the client's request).
///
/// # Budgets
///
/// Opt-in. A grant is a signed receipt attestation. Without a local
/// ceiling (or an authorizer verdict that overrides this rule) nothing
/// is granted, regardless of the client's request.
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
pub(crate) fn accept_transport(
	offer: Option<&TransportOffer>,
	local: Option<&TransportOffer>,
) -> Option<TransportAccept> {
	let offer = offer?;
	let local = local?;
	if !offer.mux || !local.mux {
		return None;
	}

	// Clamp the grant to the enforcement ceiling here, at the single
	// choke point, so the wire accept equals what the transport enforces
	// and equals what the session receipt attests (SSOT, CWE-770).
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

/// Refusal verdict from a [`TransportAuthorizer`].
///
/// Carries an application-defined code from the shared u32 code space.
///
/// # Code space
///
/// - Application codes: at or above
///   [`MUX_APPLICATION_CODE_FLOOR`](crate::transport::envelopes::MUX_APPLICATION_CODE_FLOOR).
/// - Below the floor: reserved for the protocol (e.g.
///   [`SETTLEMENT_UNSUPPORTED_CODE`]).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthorizationRefusal {
	/// Application-defined refusal code.
	pub code: u32,
}

/// Grant verdict from a [`TransportAuthorizer`].
///
/// Carries the budgets awarded and an optional settlement challenge
/// (unsigned transaction, invoice, or other opaque bytes). The challenge
/// enters the [`SessionReceipt`] body server-side and is covered by both
/// receipt signatures.
///
/// # Fail closed
///
/// A challenge without budgets has no carriage: receipts exist only for
/// budget-bearing sessions, so that combination aborts the handshake.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AuthorizationGrant {
	/// Per-direction budgets granted. `None` grants an unmetered session.
	pub budgets: Option<MuxBudgets>,
	/// Opaque settlement challenge bound into the session receipt. Never
	/// parsed by TightBeam.
	pub challenge: Option<OctetString>,
}

impl From<Option<MuxBudgets>> for AuthorizationGrant {
	fn from(budgets: Option<MuxBudgets>) -> Self {
		Self { budgets, challenge: None }
	}
}

/// Server policy for session budget grants and receipt settlement.
///
/// Two hooks, both awaited inline with **no library deadline**. Bound
/// external work yourself: a slow hook stalls per-connection handshake
/// state and widens the window an unauthenticated peer can hold it.
///
/// 1. [`authorize`](Self::authorize) - after the client
///    [`TransportOffer`], before accept enters the transcript. Inspects
///    [`TransportOffer::requested_budgets`] and the opaque
///    [`TransportOffer::authorization`] token (never parsed by
///    TightBeam). Returns an [`AuthorizationGrant`] or
///    [`AuthorizationRefusal`]. The grant is covered by the server
///    Finished signature.
///
/// 2. [`settle`](Self::settle) - after the client's countersigned
///    receipt verifies. The session activates only on `Ok`.
///
/// # Grants
///
/// - `budgets: Some(_)` - metered session. The library still clamps to
///   the componentwise minimum of the client's request before binding
///   accept and receipt.
/// - `budgets: None` - unmetered. A client that requested budgets fails
///   closed with [`BudgetGrantWithheld`](NegotiationError::BudgetGrantWithheld).
///   To deny metering, return [`AuthorizationRefusal`] instead of an
///   empty grant.
/// - A challenge without budgets fails closed
///   ([`ChallengeWithoutBudgets`](NegotiationError::ChallengeWithoutBudgets)):
///   no receipt would exist to carry it.
///
/// # When no authorizer is installed
///
/// The server uses its local accept rule alone: componentwise minimum of
/// the request and the local budget ceiling. No ceiling means nothing
/// is granted.
pub trait TransportAuthorizer: MaybeSend + MaybeSync {
	/// Grant budgets and optional settlement challenge for this offer.
	///
	/// # Errors
	///
	/// [`AuthorizationRefusal`] aborts the handshake with its application
	/// code.
	fn authorize<'a>(
		&'a self,
		offer: &'a TransportOffer,
	) -> MaybeSendFuture<'a, Result<AuthorizationGrant, AuthorizationRefusal>>;

	/// Settle the countersigned receipt at the client's key exchange.
	///
	/// Called with the receipt body and the client's ancillary response once
	/// the countersignature has verified. The session activates only on `Ok`.
	///
	/// # Default
	///
	/// Challenge-free receipts settle trivially. An authorizer that
	/// issues a challenge without overriding this method refuses every
	/// settlement with [`SETTLEMENT_UNSUPPORTED_CODE`].
	///
	/// # Errors
	///
	/// [`AuthorizationRefusal`] aborts the handshake with its application
	/// code.
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
}

/// Refusal code emitted by the default [`TransportAuthorizer::settle`]
/// when a challenge-bearing receipt reaches an authorizer that never
/// implemented settlement. Protocol-reserved (below the application code
/// floor).
pub const SETTLEMENT_UNSUPPORTED_CODE: u32 = 1;

/// Authorized transport verdict after offer/accept authorization.
///
/// - `accept` - bound into the transcript.
/// - `challenge` - settlement challenge for the session receipt body.
pub struct AuthorizedTransport {
	/// The transport accept sent to the client.
	pub accept: TransportAccept,
	/// Settlement challenge from the authorizer, carried in the receipt.
	pub challenge: Option<OctetString>,
}

/// Server-side accept path with optional [`TransportAuthorizer`].
///
/// Starts from [`accept_transport`]. When an authorizer is present its
/// grant replaces the local-config budget, still clamped to the
/// componentwise minimum of the client's request before accept and
/// receipt are bound.
///
/// # Fail closed
///
/// - Challenge without budgets: [`NegotiationError::ChallengeWithoutBudgets`]
///   (no receipt would exist to carry it).
///
/// Client consistency for unsolicited or over-request grants is enforced
/// in [`client_mux_settings`], not here.
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
pub(crate) async fn authorize_transport(
	offer: Option<&TransportOffer>,
	local: Option<&TransportOffer>,
	authorizer: Option<&dyn TransportAuthorizer>,
) -> Result<Option<AuthorizedTransport>, NegotiationError> {
	let mut accept = match accept_transport(offer, local) {
		Some(accept) => accept,
		None => return Ok(None),
	};
	let (Some(authorizer), Some(offer)) = (authorizer, offer) else {
		let authorized = AuthorizedTransport { accept, challenge: None };
		return Ok(Some(authorized));
	};

	let grant = authorizer.authorize(offer).await?;
	// The authorizer's grant is subject to the same enforcement bounds as
	// a local-config grant: the componentwise minimum with the request,
	// then the session cap, before it enters the transcript and the
	// receipt (SSOT, CWE-770). A grant beyond the request would bind the
	// client's countersignature to figures it never asked for.
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

/// `(send_budget, recv_budget)` for one endpoint role from wire grants.
///
/// `local_is_client` swaps which direction maps to local send versus
/// receive. Absent grant yields `(None, None)` (unmetered).
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
fn budget_views(granted: Option<MuxBudgets>, local_is_client: bool) -> (Option<u64>, Option<u64>) {
	let granted = match granted {
		Some(budgets) => budgets.clamped(),
		None => return (None, None),
	};

	if local_is_client {
		return (Some(granted.client_to_server), Some(granted.server_to_client));
	}

	(Some(granted.server_to_client), Some(granted.client_to_server))
}

/// Client-side settings derived from offer and accept.
///
/// Validates the server's accept against the local offer, then builds
/// directional [`MuxSettings`] through the shared clamp choke points.
///
/// # Fail closed
///
/// - Accept with no matching mux offer: [`NegotiationError::UnsolicitedTransportAccept`]
/// - Grant when none was requested: [`NegotiationError::UnsolicitedTransportAccept`]
/// - Grant beyond [`MAX_MUX_SESSION_BUDGET`]: [`NegotiationError::BudgetBeyondCap`]
/// - Grant beyond the request: [`NegotiationError::BudgetBeyondRequest`]
/// - Grant withheld when budgets were requested: [`NegotiationError::BudgetGrantWithheld`]
///
/// The receipt attests wire values, so divergences are refused rather
/// than repaired by clamping.
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
pub(crate) fn client_mux_settings(
	offer: Option<&TransportOffer>,
	accept: Option<&TransportAccept>,
) -> Result<Option<MuxSettings>, NegotiationError> {
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
	// The receipt countersigns the raw wire budgets, so clamping here
	// would attest figures the client never enforces. A grant a
	// conforming server could never emit is refused, not repaired.
	if accept.granted_budgets.is_some_and(|granted| granted != granted.clamped()) {
		return Err(NegotiationError::BudgetBeyondCap);
	}
	// Same fail-closed contract for a grant beyond the request: a
	// conforming server derives the grant as the componentwise minimum
	// with the request, so an over-request grant is refused rather than
	// countersigned at figures the client never asked for.
	if let (Some(granted), Some(requested)) = (accept.granted_budgets, offer.requested_budgets) {
		if granted != granted.min(requested) {
			return Err(NegotiationError::BudgetBeyondRequest);
		}
	}
	// Requesting budgets requests an attested, spend-bounded session. A
	// grant withheld (None against a request) is a refusal to meter:
	// running unmetered instead would silently drop the receipt, so fail
	// loud. Clients that tolerate unmetered sessions do not request budgets.
	if accept.granted_budgets.is_none() && offer.requested_budgets.is_some() {
		return Err(NegotiationError::BudgetGrantWithheld);
	}

	let settings = mux_settings(offer, accept, true);
	Ok(Some(settings))
}

/// Server-side settings from the client's offer and the accept just emitted.
///
/// Directional views are clamped through the same choke points as
/// [`client_mux_settings`].
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
pub(crate) fn server_mux_settings(offer: &TransportOffer, accept: &TransportAccept) -> MuxSettings {
	mux_settings(offer, accept, false)
}

/// Directional [`MuxSettings`] from the clamped wire values both endpoints
/// observed.
///
/// `local_is_client` selects which advertisement is local receive versus
/// peer receive.
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
fn mux_settings(offer: &TransportOffer, accept: &TransportAccept, local_is_client: bool) -> MuxSettings {
	let (send_budget, recv_budget) = budget_views(accept.granted_budgets, local_is_client);

	let local_initiated_cap;
	let peer_initiated_cap;
	let send_chunk_size;
	let recv_chunk_size;
	let initial_send_credit;
	let initial_recv_credit;
	if local_is_client {
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

/// Errors during profile negotiation.
#[derive(Debug, Clone, PartialEq, Eq, Errorizable)]
pub enum NegotiationError {
	/// No mutually supported profile found.
	#[error("No mutually supported security profile")]
	NoMutualProfile,

	/// Offer contains no profiles.
	#[error("Security offer is empty")]
	EmptyOffer,

	/// No profile meets the configured minimum-strength policy.
	#[error("No profile meets the minimum-strength policy")]
	BelowStrengthFloor,

	/// Offer exceeds the maximum accepted profile count.
	#[error("Security offer too large: {count} profiles exceeds cap of {max}")]
	OfferTooLarge { count: usize, max: usize },

	/// Peer accepted a transport capability that was never offered.
	#[error("Peer accepted a transport capability that was never offered")]
	UnsolicitedTransportAccept,

	/// The transport authorizer refused the session.
	#[error("Transport authorization refused: code {code}")]
	AuthorizationRefused { code: u32 },

	/// The authorizer issued a settlement challenge without granting
	/// budgets: the receipt that would carry it never exists.
	#[error("Settlement challenge issued without budget grant")]
	ChallengeWithoutBudgets,

	/// Peer granted budgets beyond [`MAX_MUX_SESSION_BUDGET`].
	///
	/// Receipt attests raw wire values; clamping would countersign
	/// figures the local endpoint never enforces. Fail closed.
	#[error("Granted budgets exceed the session budget cap")]
	BudgetBeyondCap,

	/// Peer granted budgets beyond the request.
	///
	/// A conforming server uses the componentwise minimum with the
	/// request. Fail closed rather than countersign unasked figures.
	#[error("Granted budgets exceed the requested budgets")]
	BudgetBeyondRequest,

	/// Peer withheld budgets for a session that requested them.
	///
	/// Requesting budgets requests attestation; silent unmetered is
	/// refused.
	#[error("Budget grant withheld for a budget-requesting session")]
	BudgetGrantWithheld,

	/// DER encoding/decoding error.
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

/// Minimum-strength filter applied to profiles before negotiation.
///
/// Blocks downgrade (CWE-757): a mutually supported weak profile is
/// still refused unless the policy admits it.
pub trait ProfileStrengthPolicy {
	/// `true` when the profile meets the policy floor.
	fn meets_floor(&self, profile: &SecurityProfileDesc) -> bool;
}

/// Default strength floor.
///
/// # Requires
///
/// - AEAD key size at least 256 bits.
/// - Known digest OID of at least 256 bits.
///
/// # Fail closed
///
/// Unknown digest OIDs do not meet the floor.
#[derive(Debug, Default, Clone, Copy)]
pub struct DefaultStrengthFloor;

/// Security strength in bits of a known digest OID. `0` for unknown OIDs (fail closed).
fn digest_bits(oid: &ObjectIdentifier) -> u16 {
	use crate::oids::{HASH_SHA256, HASH_SHA3_256, HASH_SHA3_384, HASH_SHA3_512};

	if *oid == HASH_SHA256 || *oid == HASH_SHA3_256 {
		return 256;
	}
	if *oid == HASH_SHA3_384 {
		return 384;
	}
	if *oid == HASH_SHA3_512 {
		return 512;
	}
	0
}

impl ProfileStrengthPolicy for DefaultStrengthFloor {
	fn meets_floor(&self, profile: &SecurityProfileDesc) -> bool {
		let aead_ok = matches!(profile.aead_key_size, Some(size) if size >= 32);
		let digest_ok = matches!(profile.digest.as_ref(), Some(oid) if digest_bits(oid) >= 256);
		aead_ok && digest_ok
	}
}

/// Strength policy that admits every profile.
///
/// Explicit opt-out of the minimum-strength floor. Prefer
/// [`DefaultStrengthFloor`] except for compatibility deployments or
/// downgrade-attack tests.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoStrengthFloor;

impl ProfileStrengthPolicy for NoStrengthFloor {
	fn meets_floor(&self, _profile: &SecurityProfileDesc) -> bool {
		true
	}
}

/// Select the first mutually supported profile in *local* preference order.
///
/// Iterates `supported` as configured and picks the first profile the peer
/// also offered. Peer offer ordering carries no weight: a MITM rewriting
/// it cannot steer selection toward a weaker mutual profile (CWE-757).
///
/// # Errors
///
/// - [`NegotiationError::EmptyOffer`] - peer sent an empty offer.
/// - [`NegotiationError::OfferTooLarge`] - offer exceeds [`MAX_OFFER_PROFILES`].
/// - [`NegotiationError::NoMutualProfile`] - no intersection with `supported`.
pub(crate) fn select_profile(
	offer: &SecurityOffer,
	supported: &[SecurityProfileDesc],
) -> Result<SecurityProfileDesc, NegotiationError> {
	if offer.profiles.is_empty() {
		return Err(NegotiationError::EmptyOffer);
	}
	if offer.profiles.len() > MAX_OFFER_PROFILES {
		return Err(NegotiationError::OfferTooLarge { count: offer.profiles.len(), max: MAX_OFFER_PROFILES });
	}

	for candidate in supported {
		if offer.profiles.contains(candidate) {
			return Ok(*candidate);
		}
	}

	Err(NegotiationError::NoMutualProfile)
}

// Exercises the mux negotiation helpers, which only exist when a
// transport flavor is enabled.
#[cfg(all(test, any(feature = "transport-cms", feature = "transport-ecies")))]
mod tests {
	use core::error::Error;

	use super::*;
	use crate::asn1::{AlgorithmIdentifier, DigestInfo};
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
			aead_key_size: Some(32),
			signature: Some(SIGNER_ECDSA_WITH_SHA3_512),
			kdf: Some(HASH_SHA3_256),
			curve: Some(CURVE_SECP256K1),
			key_wrap,
			kem: None,
		}
	}

	#[test]
	fn test_offer_single() {
		let profile = sample_profile(1);
		let offer = SecurityOffer::single(profile);
		assert_eq!(offer.profiles.len(), 1);
		assert_eq!(offer.profiles[0], profile);
	}

	#[test]
	fn test_select_first_mutual() -> Result<(), Box<dyn Error>> {
		let p1 = sample_profile(1);
		let p2 = sample_profile(2);
		let p3 = sample_profile(3);

		let offer = SecurityOffer::new(Vec::from([p1, p2, p3]));
		let supported = [p2, p3];

		let selected = select_profile(&offer, &supported)?;
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

		let selected = select_profile(&offer, &supported)?;
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

		let result = select_profile(&offer, &supported);
		assert!(matches!(result, Err(NegotiationError::NoMutualProfile)));
	}

	#[test]
	fn test_oversized_offer_rejected() {
		let profile = sample_profile(1);
		let offer = SecurityOffer::new(vec![profile; MAX_OFFER_PROFILES + 1]);
		let supported = [profile];

		let result = select_profile(&offer, &supported);
		assert!(matches!(result, Err(NegotiationError::OfferTooLarge { count: 33, max: 32 })));
	}

	#[test]
	fn test_empty_offer() {
		let offer = SecurityOffer::new(Vec::new());
		let supported = [sample_profile(1)];

		let result = select_profile(&offer, &supported);
		assert!(matches!(result, Err(NegotiationError::EmptyOffer)));
	}

	fn disabled_offer(cap: u32) -> TransportOffer {
		TransportOffer { mux: false, ..TransportOffer::mux(cap) }
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
		let settings = client_mux_settings(Some(offer), Some(accept))?;
		settings.ok_or(NegotiationError::UnsolicitedTransportAccept)
	}

	#[test]
	fn test_accept_transport_activates_when_both_enable_mux() {
		let offer = TransportOffer::mux(8);
		let local = TransportOffer::mux(4);

		let accept = accept_transport(Some(&offer), Some(&local));
		assert!(matches!(
			accept,
			Some(TransportAccept { mux: true, max_peer_initiated_streams: 4, .. })
		));
	}

	#[test]
	fn test_accept_transport_absent_offer_declines() {
		let local = TransportOffer::mux(4);
		assert!(accept_transport(None, Some(&local)).is_none());
	}

	#[test]
	fn test_accept_transport_absent_local_declines() {
		let offer = TransportOffer::mux(8);
		assert!(accept_transport(Some(&offer), None).is_none());
	}

	#[test]
	fn test_accept_transport_disabled_offer_declines() {
		let disabled = disabled_offer(8);
		let local = TransportOffer::mux(4);
		assert!(accept_transport(Some(&disabled), Some(&local)).is_none());
	}

	#[test]
	fn test_accept_transport_disabled_local_declines() {
		let offer = TransportOffer::mux(8);
		let disabled = disabled_offer(4);
		assert!(accept_transport(Some(&offer), Some(&disabled)).is_none());
	}

	#[test]
	fn test_accept_transport_grants_min_of_request_and_ceiling() {
		let request = MuxBudgets { client_to_server: 100, server_to_client: 900 };
		let ceiling = MuxBudgets { client_to_server: 500, server_to_client: 300 };
		let offer = TransportOffer::mux(8).with_budgets(request);
		let local = TransportOffer::mux(4).with_budgets(ceiling);

		let accept = accept_transport(Some(&offer), Some(&local));
		let granted = accept.and_then(|accept| accept.granted_budgets);
		assert_eq!(granted, Some(MuxBudgets { client_to_server: 100, server_to_client: 300 }));
	}

	#[test]
	fn test_accept_transport_grants_nothing_unrequested() {
		let ceiling = MuxBudgets { client_to_server: 500, server_to_client: 300 };
		let offer = TransportOffer::mux(8);
		let local = TransportOffer::mux(4).with_budgets(ceiling);

		let accept = accept_transport(Some(&offer), Some(&local));
		let granted = accept.and_then(|accept| accept.granted_budgets);
		assert_eq!(granted, None);
	}

	#[test]
	fn test_accept_transport_without_ceiling_grants_nothing() {
		let request = MuxBudgets { client_to_server: 100, server_to_client: 900 };
		let offer = TransportOffer::mux(8).with_budgets(request);
		let local = TransportOffer::mux(4);

		let accept = accept_transport(Some(&offer), Some(&local));
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

		let accept = authorize_transport(Some(&offer), Some(&local), None).await?;
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

		let accept = authorize_transport(Some(&offer), Some(&local), Some(&authorizer)).await?;
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

		let accept = authorize_transport(Some(&offer), Some(&local), Some(&authorizer)).await?;
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

		let result = authorize_transport(Some(&offer), Some(&local), Some(&authorizer)).await;
		assert!(matches!(result, Err(NegotiationError::AuthorizationRefused { code: 7 })));
	}

	#[tokio::test]
	async fn test_authorize_transport_masks_unsolicited_grant() -> Result<(), NegotiationError> {
		let verdict = MuxBudgets { client_to_server: 40, server_to_client: 60 };
		let offer = TransportOffer::mux(8);
		let local = TransportOffer::mux(4);
		let authorizer = FixedAuthorizer::budgets(Ok(Some(verdict)));

		let accept = authorize_transport(Some(&offer), Some(&local), Some(&authorizer)).await?;
		let granted = accept.and_then(|authorized| authorized.accept.granted_budgets);
		assert_eq!(granted, None);

		Ok(())
	}

	#[tokio::test]
	async fn test_authorize_transport_inactive_mux_skips_authorizer() -> Result<(), NegotiationError> {
		let offer = TransportOffer::mux(8);
		let authorizer = FixedAuthorizer::budgets(Err(AuthorizationRefusal { code: 7 }));

		let accept = authorize_transport(Some(&offer), None, Some(&authorizer)).await?;
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

		let authorized = authorize_transport(Some(&offer), Some(&local), Some(&authorizer)).await?;
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

		let result = authorize_transport(Some(&offer), Some(&local), Some(&authorizer)).await;
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

		let server = server_mux_settings(&offer, &accept);
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

		let server = server_mux_settings(&offer, &accept);
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

		let server = server_mux_settings(&offer, &accept);
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

		let server = server_mux_settings(&offer, &accept);
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

		let result = client_mux_settings(None, Some(&accept));
		assert!(matches!(result, Err(NegotiationError::UnsolicitedTransportAccept)));

		let disabled = disabled_offer(8);
		let result = client_mux_settings(Some(&disabled), Some(&accept));
		assert!(matches!(result, Err(NegotiationError::UnsolicitedTransportAccept)));
	}

	#[test]
	fn test_unsolicited_granted_budget_fails_closed() {
		let offer = TransportOffer::mux(8);
		let budgets = MuxBudgets { client_to_server: 100, server_to_client: 300 };
		let accept = TransportAccept { granted_budgets: Some(budgets), ..plain_accept(4) };

		let result = client_mux_settings(Some(&offer), Some(&accept));
		assert!(matches!(result, Err(NegotiationError::UnsolicitedTransportAccept)));
	}

	#[test]
	fn test_over_cap_granted_budget_fails_closed() {
		let over_cap = MuxBudgets { client_to_server: MAX_MUX_SESSION_BUDGET + 1, server_to_client: 1 };
		let offer = TransportOffer::mux(8).with_budgets(over_cap);
		let accept = TransportAccept { granted_budgets: Some(over_cap), ..plain_accept(4) };

		let result = client_mux_settings(Some(&offer), Some(&accept));
		assert!(matches!(result, Err(NegotiationError::BudgetBeyondCap)));
	}

	#[test]
	fn test_over_request_granted_budget_fails_closed() {
		let request = MuxBudgets { client_to_server: 100, server_to_client: 300 };
		let over_request = MuxBudgets { client_to_server: 100, server_to_client: 301 };
		let offer = TransportOffer::mux(8).with_budgets(request);
		let accept = TransportAccept { granted_budgets: Some(over_request), ..plain_accept(4) };

		let result = client_mux_settings(Some(&offer), Some(&accept));
		assert!(matches!(result, Err(NegotiationError::BudgetBeyondRequest)));
	}

	#[test]
	fn test_withheld_budget_grant_fails_closed() {
		let request = MuxBudgets { client_to_server: 100, server_to_client: 300 };
		let offer = TransportOffer::mux(8).with_budgets(request);
		let accept = plain_accept(4);

		let result = client_mux_settings(Some(&offer), Some(&accept));
		assert!(matches!(result, Err(NegotiationError::BudgetGrantWithheld)));
	}

	#[test]
	fn test_no_accept_means_mux_inactive() -> Result<(), NegotiationError> {
		let offer = TransportOffer::mux(8);
		assert!(client_mux_settings(Some(&offer), None)?.is_none());
		assert!(client_mux_settings(None, None)?.is_none());

		let declined = TransportAccept { mux: false, ..plain_accept(0) };
		assert!(client_mux_settings(Some(&offer), Some(&declined))?.is_none());

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
			aead_key_size: Some(16),
			signature: Some(SIGNER_ECDSA_WITH_SHA256),
			kdf: Some(HASH_SHA256),
			curve: Some(CURVE_SECP256K1),
			key_wrap: Some(AES_128_WRAP),
			kem: None,
		};
		let aes256_gcm = SecurityProfileDesc {
			digest: Some(HASH_SHA256),
			aead: Some(AES_256_GCM),
			aead_key_size: Some(32),
			signature: Some(SIGNER_ECDSA_WITH_SHA256),
			kdf: Some(HASH_SHA256),
			curve: Some(CURVE_SECP256K1),
			key_wrap: Some(AES_256_WRAP),
			kem: None,
		};

		let cases: [(&[SecurityProfileDesc], &[SecurityProfileDesc], ObjectIdentifier, u16); 4] = [
			(&[aes128_gcm, aes256_gcm], &[aes256_gcm, aes128_gcm], AES_256_GCM, 32),
			(&[aes256_gcm, aes128_gcm], &[aes256_gcm, aes128_gcm], AES_256_GCM, 32),
			(&[aes256_gcm, aes128_gcm], &[aes128_gcm, aes256_gcm], AES_128_GCM, 16),
			(&[aes128_gcm, aes256_gcm], &[aes256_gcm], AES_256_GCM, 32),
		];

		for (client_profiles, server_profiles, expected_aead, expected_key_size) in cases {
			let offer = SecurityOffer::new(client_profiles.to_vec());
			let selected = select_profile(&offer, server_profiles)?;
			assert_eq!(selected.aead, Some(expected_aead));
			assert_eq!(selected.aead_key_size, Some(expected_key_size));
		}

		Ok(())
	}
}
