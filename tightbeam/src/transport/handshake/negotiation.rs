//! Security profile negotiation for TightBeam handshakes.
//!
//! Provides minimal wire-level structures (Offer, Accept) for algorithm
//! negotiation without forcing concrete algorithm instantiation during the
//! negotiation phase.

#[cfg(not(feature = "std"))]
extern crate alloc;

use crate::constants::{
	DEFAULT_MUX_CHUNK_SIZE, DEFAULT_MUX_CREDIT_UNIT, DEFAULT_MUX_STREAM_CREDIT, MAX_MUX_CHUNK_SIZE,
	MAX_MUX_SESSION_BUDGET, MAX_MUX_STREAM_CAP, MAX_MUX_STREAM_CREDIT, MIN_MUX_CHUNK_SIZE,
};
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

/// Handshake offer carrying a list of supported security profiles.
///
/// Client sends this to advertise which algorithm combinations it supports.
/// Serializable to DER for wire transmission.
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

/// Handshake accept response carrying the selected security profile.
///
/// Server sends this after selecting a mutually supported profile from the client's offer.
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
/// A credit is the abstract TightBeam volume unit: a data chunk debits
/// `ceil(payload_len / credit_unit)` credits from its sender's direction.
/// Budgets are fixed per key epoch and only shrink inside an epoch. Value
/// semantics (free, fiat, anything) live outside the protocol.
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
	fn clamped(self) -> MuxBudgets {
		MuxBudgets {
			client_to_server: self.client_to_server.min(MAX_MUX_SESSION_BUDGET),
			server_to_client: self.server_to_client.min(MAX_MUX_SESSION_BUDGET),
		}
	}
}

/// Transport capability offer (multiplexing).
///
/// Each side advertises how many streams its *peer* may concurrently initiate
/// ([RFC 9113 § 5.1.2](https://datatracker.ietf.org/doc/html/rfc9113#section-5.1.2)
/// directional semantics). Sent by the client inside its handshake opening
/// message so the offer is bound into the transcript. Chunk size and stream
/// credit are equally directional: the sender of the struct advertises what
/// it will *receive*. Budgets and the authorization token flow client to
/// server only.
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

/// Transport capability accept (multiplexing).
///
/// Same directional shape as [`TransportOffer`]: the server advertises the
/// stream cap, chunk size, and stream credit it will *receive*. The accept
/// additionally fixes the credit unit for both directions and carries the
/// budgets actually granted (each direction lower than requested or zero
/// is allowed). Sent inside the server's handshake response and bound into
/// the transcript.
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

/// Negotiated multiplexing settings for one connection.
///
/// Caps, chunk sizes, and stream credit are directional
/// ([RFC 9113 § 5.1.2](https://datatracker.ietf.org/doc/html/rfc9113#section-5.1.2)):
/// each endpoint enforces the value it advertised and respects the value its
/// peer advertised. There is no symmetric min-collapse. Both endpoints
/// derive their views from the same clamped wire values, so enforcement
/// stays consistent.
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
	/// Equal caps in both directions with default chunking and credit
	/// values, for links without handshake negotiation (cleartext
	/// multiplexing). Budgets stay unmetered: without an encrypted
	/// session there is no epoch to renew, so a spendable bound would be
	/// unrecoverable. Both endpoints MUST configure the same value or
	/// their enforcement diverges. The cap is clamped to
	/// [`MAX_MUX_STREAM_CAP`].
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
fn clamp_chunk_size(size: u32) -> u32 {
	size.clamp(MIN_MUX_CHUNK_SIZE, MAX_MUX_CHUNK_SIZE)
}

/// Clamp a wire-advertised credit unit to at least one byte so debit
/// arithmetic never divides by zero.
fn clamp_credit_unit(unit: u32) -> u32 {
	unit.max(1)
}

/// Clamp a wire-advertised initial stream credit window into
/// `1..=MAX_MUX_STREAM_CREDIT`. The ceiling bounds receive memory
/// (CWE-770). The floor of one chunk keeps every stream startable, since
/// credit grants only flow once a first chunk has arrived.
fn clamp_stream_credit(credit: u64) -> u64 {
	credit.clamp(1, MAX_MUX_STREAM_CREDIT)
}

/// Server-side accept rule: multiplexing activates only when the peer
/// offered it AND it is locally enabled. No offer or no local config means
/// no accept, so both endpoints stay on the same activation decision.
///
/// The local [`TransportOffer`] doubles as server configuration: its
/// receive-side values are advertised back, its `requested_budgets` acts
/// as the grant ceiling, the componentwise minimum with the request.
/// Nothing requested means nothing granted.
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
		(None, _) => None,
		(Some(requested), None) => Some(requested.clamped()),
		(Some(requested), Some(ceiling)) => Some(requested.min(ceiling).clamped()),
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

/// Refusal verdict from a [`TransportAuthorizer`], carrying an
/// application-defined code from the shared u32 code space.
///
/// Application codes live at or above
/// [`MUX_APPLICATION_CODE_FLOOR`](crate::transport::envelopes::MUX_APPLICATION_CODE_FLOOR).
/// Codes below the floor are reserved for the TightBeam protocol (e.g.
/// [`SETTLEMENT_UNSUPPORTED_CODE`]).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthorizationRefusal {
	/// Application-defined refusal code.
	pub code: u32,
}

/// Grant verdict from a [`TransportAuthorizer`]: the budgets awarded plus
/// an optional settlement challenge.
///
/// The challenge (unsigned transaction, invoice, anything opaque) enters
/// the [`SessionReceipt`] body server-side, so it is covered by both
/// receipt signatures. A challenge without budgets has no carriage. The
/// receipt only exists for budget-bearing sessions and fails the
/// handshake closed.
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

/// Server hook between transport offer and accept: decides the
/// per-direction budgets granted for the session described by the
/// offer (its `requested_budgets` and opaque `authorization` token,
/// which TightBeam never parses) and optionally attaches a settlement
/// challenge. Runs before the accept is bound into the transcript, so
/// the grant is covered by the server signature.
///
/// Without an authorizer the server grants its local configuration:
/// the componentwise minimum of the request and the local ceiling (see
/// [`accept_transport`]). A grant with `budgets: None` is an unmetered
/// session. A refusal aborts the handshake with its application code.
///
/// Both hooks are awaited inline in the handshake with no library
/// deadline, while the server holds per-connection handshake state: a
/// slow authorizer stalls the handshake and extends the window an
/// unauthenticated peer can hold that state, so bound external lookups
/// with your own timeout.
pub trait TransportAuthorizer: MaybeSend + MaybeSync {
	/// Decide the budgets granted and the settlement challenge issued
	/// for the session.
	fn authorize<'a>(
		&'a self,
		offer: &'a TransportOffer,
	) -> MaybeSendFuture<'a, Result<AuthorizationGrant, AuthorizationRefusal>>;

	/// Settle the countersigned receipt at the client's key exchange.
	///
	/// Called with the receipt body and the client's ancillary response
	/// once the countersignature has verified. The session activates only
	/// after `Ok`. A refusal aborts the handshake with its application
	/// code.
	///
	/// Fails closed by default: an authorizer that issues a challenge
	/// without overriding this method refuses every settlement (code
	/// [`SETTLEMENT_UNSUPPORTED_CODE`]). Challenge-free receipts settle
	/// trivially.
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

/// Authorized transport verdict: the accept bound into the transcript
/// plus the settlement challenge destined for the session receipt.
pub struct AuthorizedTransport {
	/// The transport accept sent to the client.
	pub accept: TransportAccept,
	/// Settlement challenge from the authorizer, carried in the receipt.
	pub challenge: Option<OctetString>,
}

/// Server-side accept rule with the authorizer consulted between offer
/// and accept. Without an authorizer this is exactly
/// [`accept_transport`]. With one, the authorizer's verdict replaces
/// the local-config budget grant. Budgets only activate against a
/// request: an unsolicited grant fails the client's consistency check
/// in [`client_mux_settings`]. A challenge granted without budgets
/// fails closed: the receipt that would carry it never exists.
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
	// The authorizer's grant is subject to the same enforcement ceiling as
	// a local-config grant: clamp before it enters the transcript and the
	// receipt (SSOT, CWE-770).
	let requested = offer.requested_budgets;
	let granted = grant.budgets;
	let granted_budgets = requested.and(granted).map(MuxBudgets::clamped);
	accept.granted_budgets = granted_budgets;

	let challenge = grant.challenge;
	if challenge.is_some() && accept.granted_budgets.is_none() {
		return Err(NegotiationError::ChallengeWithoutBudgets);
	}

	let authorized = AuthorizedTransport { accept, challenge };
	Ok(Some(authorized))
}

/// Directional budget view for one endpoint role, derived from the
/// granted budgets both sides saw on the wire.
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

/// Client-side settings rule: validates the server's accept against the
/// local offer and derives the directional views, each clamped through
/// the shared choke points.
///
/// An accept without a matching offer is a protocol violation (a peer must
/// never activate an unrequested capability) and fails closed. So is a
/// granted budget when none was requested, or one beyond
/// [`MAX_MUX_SESSION_BUDGET`]: the receipt attests the wire values, so an
/// over-cap grant is refused rather than silently clamped.
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

	let settings = mux_settings(offer, accept, true);
	Ok(Some(settings))
}

/// Server-side settings rule: derives the directional views from the
/// client's offer and the accept the server just emitted, each clamped
/// through the shared choke points.
pub(crate) fn server_mux_settings(offer: &TransportOffer, accept: &TransportAccept) -> MuxSettings {
	mux_settings(offer, accept, false)
}

/// Derive directional [`MuxSettings`] from the same clamped wire values
/// both endpoints observed. `local_is_client` selects which advertisement
/// is local receive versus peer receive.
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
#[cfg_attr(feature = "derive", derive(Errorizable))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NegotiationError {
	/// No mutually supported profile found.
	#[cfg_attr(feature = "derive", error("No mutually supported security profile"))]
	NoMutualProfile,

	/// Offer contains no profiles.
	#[cfg_attr(feature = "derive", error("Security offer is empty"))]
	EmptyOffer,

	/// No profile meets the configured minimum-strength policy.
	#[cfg_attr(feature = "derive", error("No profile meets the minimum-strength policy"))]
	BelowStrengthFloor,

	/// Offer exceeds the maximum accepted profile count.
	#[cfg_attr(
		feature = "derive",
		error("Security offer too large: {count} profiles exceeds cap of {max}")
	)]
	OfferTooLarge { count: usize, max: usize },

	/// Peer accepted a transport capability that was never offered.
	#[cfg_attr(
		feature = "derive",
		error("Peer accepted a transport capability that was never offered")
	)]
	UnsolicitedTransportAccept,

	/// The transport authorizer refused the session.
	#[cfg_attr(feature = "derive", error("Transport authorization refused: code {code}"))]
	AuthorizationRefused { code: u32 },

	/// The authorizer issued a settlement challenge without granting
	/// budgets: the receipt that would carry it never exists.
	#[cfg_attr(feature = "derive", error("Settlement challenge issued without budget grant"))]
	ChallengeWithoutBudgets,

	/// The peer granted budgets beyond [`MAX_MUX_SESSION_BUDGET`]. The
	/// receipt attests the raw wire values, so an over-cap grant would
	/// be countersigned at figures the local endpoint never enforces
	/// (dispute ambiguity). Fail closed instead of clamping.
	#[cfg_attr(feature = "derive", error("Granted budgets exceed the session budget cap"))]
	BudgetBeyondCap,

	/// DER encoding/decoding error.
	#[cfg_attr(feature = "derive", error("DER encoding error: {0}"))]
	DerError(DerDecodeError),
}

crate::impl_error_display!(NegotiationError {
	NoMutualProfile => "No mutually supported security profile",
	EmptyOffer => "Security offer is empty",
	BelowStrengthFloor => "No profile meets the minimum-strength policy",
	OfferTooLarge { count, max } => "Security offer too large: {count} profiles exceeds cap of {max}",
	UnsolicitedTransportAccept => "Peer accepted a transport capability that was never offered",
	AuthorizationRefused { code } => "Transport authorization refused: code {code}",
	ChallengeWithoutBudgets => "Settlement challenge issued without budget grant",
	BudgetBeyondCap => "Granted budgets exceed the session budget cap",
	DerError(e) => "DER encoding error: {e}",
});

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

/// Minimum-strength policy applied to profiles before negotiation.
///
/// Prevents downgrade attacks (CWE-757): even when a weak profile is mutually
/// supported, negotiation refuses it unless the policy admits it.
pub trait ProfileStrengthPolicy {
	/// Returns `true` when the profile meets the policy floor.
	fn meets_floor(&self, profile: &SecurityProfileDesc) -> bool;
}

/// Default strength floor: 256-bit AEAD key and a known digest of at least 256 bits.
///
/// Unknown digest OIDs fail closed.
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

/// Accepts every profile. Explicitly opts out of the minimum-strength floor.
///
/// Use only where weaker profiles must remain negotiable (e.g. compatibility
/// deployments or downgrade-attack tests). Prefer [`DefaultStrengthFloor`].
#[derive(Debug, Default, Clone, Copy)]
pub struct NoStrengthFloor;

impl ProfileStrengthPolicy for NoStrengthFloor {
	fn meets_floor(&self, _profile: &SecurityProfileDesc) -> bool {
		true
	}
}

/// Select the first mutually supported profile in *local* (server) preference order.
///
/// Iterates `supported` in its configured order and picks the first profile the
/// peer also offered. The peer's ordering carries no weight: a MITM rewriting
/// the offer ordering cannot steer selection toward a weaker mutual profile
/// (CWE-757).
///
/// # Errors
///
/// - [`NegotiationError::EmptyOffer`] -- peer sent an empty offer.
/// - [`NegotiationError::OfferTooLarge`] -- offer exceeds [`MAX_OFFER_PROFILES`].
/// - [`NegotiationError::NoMutualProfile`] -- no intersection with `supported`.
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

#[cfg(test)]
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
	fn test_accept_transport_grants_request_without_ceiling() {
		let request = MuxBudgets { client_to_server: 100, server_to_client: 900 };
		let offer = TransportOffer::mux(8).with_budgets(request);
		let local = TransportOffer::mux(4);

		let accept = accept_transport(Some(&offer), Some(&local));
		let granted = accept.and_then(|accept| accept.granted_budgets);
		assert_eq!(granted, Some(request));
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
