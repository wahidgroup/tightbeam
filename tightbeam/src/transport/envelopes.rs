//! The DER data structures of the transport-layer envelopes.

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(all(not(feature = "std"), feature = "x509"))]
use alloc::boxed::Box;
#[cfg(not(feature = "std"))]
use alloc::sync::Arc;
#[cfg(all(not(feature = "std"), feature = "transport-multiplex"))]
use alloc::vec::Vec;
#[cfg(feature = "std")]
use std::sync::Arc;

use crate::asn1::Frame;
use crate::cms::enveloped_data::EncryptedContentInfo;
use crate::der::{Choice, Decode, Encode, EncodeValue, Length, Reader, Result as DerResult, Tag, Tagged, Writer};
use crate::policy::TransitStatus;
use crate::Beamable;

#[cfg(all(
	feature = "transport-multiplex",
	feature = "x509",
	any(feature = "tokio", feature = "async-transport")
))]
use crate::transport::error::TransportError;

#[cfg(feature = "transport-multiplex")]
mod multiplex {
	pub use crate::cms::signed_data::SignerInfo;
	pub use crate::constants::DEFAULT_HOP_BUDGET;
	pub use crate::der::asn1::OctetString;
	pub use crate::der::Enumerated;
	pub use crate::der::Sequence;
	pub use crate::der::{DecodeValue, FixedTag, Header};
	pub use crate::utils::urn::Urn;
}

#[cfg(feature = "transport-multiplex")]
use multiplex::*;

#[cfg(feature = "x509")]
mod x509 {
	pub use crate::cms::enveloped_data::EnvelopedData;
	pub use crate::cms::signed_data::SignedData;
	pub use crate::transport::wire_der::WireDer;
}

#[cfg(feature = "x509")]
use x509::*;

/// A request package that carries the message frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestPackage {
	pub(crate) message: Arc<Frame>,
}

impl RequestPackage {
	/// A request that carries `message`.
	pub fn new(message: Frame) -> Self {
		Self { message: Arc::new(message) }
	}

	/// The request frame, shared so a reader takes a handle rather than a copy.
	pub fn message(&self) -> &Arc<Frame> {
		&self.message
	}
}

impl EncodeValue for RequestPackage {
	fn value_len(&self) -> DerResult<Length> {
		self.message.as_ref().encoded_len()
	}

	fn encode_value(&self, writer: &mut impl Writer) -> DerResult<()> {
		self.message.as_ref().encode(writer)
	}
}

impl Tagged for RequestPackage {
	fn tag(&self) -> Tag {
		Tag::Sequence
	}
}

impl<'a> Decode<'a> for RequestPackage {
	fn decode<R: Reader<'a>>(reader: &mut R) -> DerResult<Self> {
		reader.sequence(|reader| {
			let frame = Frame::decode(reader)?;
			Ok(Self { message: Arc::new(frame) })
		})
	}
}

/// A response package that carries a status and an optional message.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ResponsePackage {
	pub(crate) status: TransitStatus,
	pub(crate) message: Option<Arc<Frame>>,
}

impl ResponsePackage {
	/// Terminal response for a unary or streaming service outcome.
	///
	/// The inverse of [`Self::resolve`]: a success carries the frame, and a
	/// failure carries its status alone. The two together are the whole
	/// round trip of one service call.
	#[cfg(pooled_mux)]
	pub(crate) fn from_outcome(outcome: Result<Option<Frame>, crate::TightBeamError>) -> Self {
		match outcome {
			Ok(message) => Self::new(TransitStatus::Ok, message),
			Err(error) => Self::new(error.failure_status(), None),
		}
	}

	/// The caller-facing result this response carries.
	///
	/// A non-[`TransitStatus::Ok`] status is the error, so a caller reads
	/// the frame only where the responder reported success.
	///
	/// The frame moves out of its `Arc` where this is the last holder, and
	/// copies only where the inbound path still shares it.
	///
	/// # Errors
	///
	/// - [`TransportError`] -- for any status other than [`TransitStatus::Ok`].
	#[cfg(all(
		feature = "transport-multiplex",
		feature = "x509",
		any(feature = "tokio", feature = "async-transport")
	))]
	pub(crate) fn resolve(self) -> Result<Option<Frame>, TransportError> {
		match self.status {
			TransitStatus::Ok => Ok(self
				.message
				.map(|frame| Arc::try_unwrap(frame).unwrap_or_else(|shared| (*shared).clone()))),
			status => Err(TransportError::from(status)),
		}
	}

	/// A response with `status` and the optional `message`.
	pub fn new(status: TransitStatus, message: Option<Frame>) -> Self {
		Self { status, message: message.map(Arc::new) }
	}

	/// The status the responder reported.
	pub fn status(&self) -> TransitStatus {
		self.status
	}

	/// The response frame, present when the responder sent one.
	pub fn message(&self) -> Option<&Arc<Frame>> {
		self.message.as_ref()
	}
}

impl EncodeValue for ResponsePackage {
	fn value_len(&self) -> DerResult<Length> {
		let message_len = match &self.message {
			Some(arc) => arc.as_ref().encoded_len()?,
			None => Length::ZERO,
		};
		[self.status.encoded_len()?, message_len]
			.into_iter()
			.try_fold(Length::ZERO, |acc, len| acc + len)
	}

	fn encode_value(&self, writer: &mut impl Writer) -> DerResult<()> {
		self.status.encode(writer)?;
		if let Some(arc) = &self.message {
			arc.as_ref().encode(writer)?;
		}

		Ok(())
	}
}

impl Tagged for ResponsePackage {
	fn tag(&self) -> Tag {
		Tag::Sequence
	}
}

impl<'a> Decode<'a> for ResponsePackage {
	fn decode<R: Reader<'a>>(reader: &mut R) -> DerResult<Self> {
		reader.sequence(|reader| {
			let status = TransitStatus::decode(reader)?;
			let message: Option<Frame> = Option::<Frame>::decode(reader)?;
			Ok(Self { status, message: message.map(Arc::new) })
		})
	}
}

/// The first u32 code that applications own in the multiplexing reason-code
/// space.
///
/// Codes below the floor are reserved for the TightBeam protocol. HTTP/2
/// error codes and QUIC application-close codes set the precedent.
///
/// # Sources
///
/// - [RFC 9113 § 7](https://datatracker.ietf.org/doc/html/rfc9113#section-7)
/// - [RFC 9000 § 20.2](https://datatracker.ietf.org/doc/html/rfc9000#section-20.2)
#[cfg(feature = "transport-multiplex")]
pub const MUX_APPLICATION_CODE_FLOOR: u32 = 0x1000;

/// The reason a single stream was cancelled
/// ([RFC 9113 § 6.4][rfc9113-6.4]).
///
/// The u32 code space is open:
///
/// - A known TB-reserved code decodes to its named variant.
/// - Every other code round-trips through [`CancelReason::Application`], so an
///   unknown code never kills a connection.
/// - `Application(code)` with a TB-reserved `code` canonicalizes to the named variant on decode.
///
/// [rfc9113-6.4]: https://datatracker.ietf.org/doc/html/rfc9113#section-6.4
#[cfg(feature = "transport-multiplex")]
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
pub enum CancelReason {
	/// The requester withdrew its interest in the response.
	#[default]
	Cancelled,
	/// The per-stream deadline elapsed before a response arrived.
	Timeout,
	/// The responder refused to process the stream.
	Rejected,
	/// An application-defined code at or above
	/// [`MUX_APPLICATION_CODE_FLOOR`], or a TB code newer than this build.
	Application(u32),
}

#[cfg(feature = "transport-multiplex")]
impl From<CancelReason> for u32 {
	fn from(reason: CancelReason) -> u32 {
		match reason {
			CancelReason::Cancelled => 0,
			CancelReason::Timeout => 1,
			CancelReason::Rejected => 2,
			CancelReason::Application(code) => code,
		}
	}
}

#[cfg(feature = "transport-multiplex")]
impl From<u32> for CancelReason {
	fn from(code: u32) -> Self {
		match code {
			0 => Self::Cancelled,
			1 => Self::Timeout,
			2 => Self::Rejected,
			code => Self::Application(code),
		}
	}
}

/// The reason the connection is shutting down
/// ([RFC 9113 § 6.8][rfc9113-6.8]).
///
/// The open u32 code space follows the rules of [`CancelReason`].
///
/// [rfc9113-6.8]: https://datatracker.ietf.org/doc/html/rfc9113#section-6.8
#[cfg(feature = "transport-multiplex")]
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
pub enum GoAwayReason {
	/// The sender initiated an orderly shutdown.
	#[default]
	Shutdown,
	/// The peer violated the multiplexing protocol.
	ProtocolError,
	/// The peer exceeded the cancel budget. This is the ENHANCE_YOUR_CALM code
	/// of [RFC 9113 § 7][rfc9113-7], and it hardens against CVE-2023-44487.
	///
	/// [rfc9113-7]: https://datatracker.ietf.org/doc/html/rfc9113#section-7
	EnhanceYourCalm,
	/// The session budget is spent down to the drain headroom. The epoch's
	/// negotiated data volume is exhausted, and the sender is draining.
	BudgetExhausted,
	/// Settlement of the session agreement failed, or was revoked after
	/// activation.
	SettlementFailed,
	/// An application-defined code at or above
	/// [`MUX_APPLICATION_CODE_FLOOR`], or a TB code newer than this build.
	Application(u32),
}

#[cfg(feature = "transport-multiplex")]
impl GoAwayReason {
	/// The stable kebab-case name for audit labels.
	///
	/// Application codes share one label and stay distinguishable by their
	/// numeric code.
	pub fn as_str(&self) -> &'static str {
		match self {
			Self::Shutdown => "shutdown",
			Self::ProtocolError => "protocol-error",
			Self::EnhanceYourCalm => "enhance-your-calm",
			Self::BudgetExhausted => "budget-exhausted",
			Self::SettlementFailed => "settlement-failed",
			Self::Application(_) => "application",
		}
	}
}

#[cfg(feature = "transport-multiplex")]
impl From<GoAwayReason> for u32 {
	fn from(reason: GoAwayReason) -> u32 {
		match reason {
			GoAwayReason::Shutdown => 0,
			GoAwayReason::ProtocolError => 1,
			GoAwayReason::EnhanceYourCalm => 2,
			GoAwayReason::BudgetExhausted => 3,
			GoAwayReason::SettlementFailed => 4,
			GoAwayReason::Application(code) => code,
		}
	}
}

#[cfg(feature = "transport-multiplex")]
impl From<u32> for GoAwayReason {
	fn from(code: u32) -> Self {
		match code {
			0 => Self::Shutdown,
			1 => Self::ProtocolError,
			2 => Self::EnhanceYourCalm,
			3 => Self::BudgetExhausted,
			4 => Self::SettlementFailed,
			code => Self::Application(code),
		}
	}
}

/// Chunk-bearing stream packages share one DER shape, and only the CHOICE
/// tag on [`MuxEnvelope`] tells them apart.
#[cfg(feature = "transport-multiplex")]
macro_rules! mux_chunk_package {
	($(#[$outer:meta])* $name:ident, last: $last_doc:literal) => {
		$(#[$outer])*
		#[derive(Sequence, Debug, Clone, PartialEq, Eq)]
		pub struct $name {
			pub(crate) stream_id: u32,
			pub(crate) last: bool,
			pub(crate) payload: OctetString,
		}

		impl $name {
			/// Build a chunk package.
			///
			/// # Errors
			///
			/// - A DER length error when `payload` is longer than the DER length cap.
			pub fn new(stream_id: u32, last: bool, payload: impl Into<Vec<u8>>) -> DerResult<Self> {
				let payload = OctetString::new(payload)?;
				Ok(Self { stream_id, last, payload })
			}

			/// The stream this chunk belongs to.
			pub fn stream_id(&self) -> u32 {
				self.stream_id
			}

			#[doc = $last_doc]
			pub fn last(&self) -> bool {
				self.last
			}

			/// The chunk payload bytes.
			pub fn payload(&self) -> &[u8] {
				self.payload.as_bytes()
			}
		}
	};
}

/// The interaction shape of a mux stream, which the initiating call stamps
/// on the Open record.
///
/// It tells the responder whether the body reassembles into one [`Frame`]
/// and which reply shape the initiator awaits, so dispatch needs no
/// heuristics.
#[cfg(feature = "transport-multiplex")]
#[derive(Enumerated, Default, Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MuxStreamKind {
	/// The body reassembles into one frame, and the reply is a unary `End`.
	#[default]
	Unary = 0,
	/// The body is consumed incrementally, and the reply is a unary `End`.
	Streaming = 1,
	/// The body is consumed incrementally, and the reply streams back as
	/// `Data*` records ahead of the closing trailer.
	Duplex = 2,
}

/// Open a stream and carry its first payload chunk inline.
///
/// All streams share one grammar ([RFC 9113 § 8.1][rfc9113-8.1]):
///
/// ```text
/// initiator:  Open(kind, last?)  Data(...)*  Data(last)
/// responder:  Data(...)*         End(status, payload?)
/// either:     Cancel(code)       Credit(limit)
/// ```
///
/// - A unary request whose frame fits one chunk is a single `Open(last = true)` record.
/// - Chunks concatenate in arrival order into the message frame DER. The
///   ordered AEAD channel with strict counter sequencing already proves order
///   and completeness, so chunks carry no sequence numbers.
/// - Stream correlation metadata travels inside the encrypted envelope payload.
///
/// [rfc9113-8.1]: https://datatracker.ietf.org/doc/html/rfc9113#section-8.1
#[cfg(feature = "transport-multiplex")]
#[derive(Sequence, Debug, Clone, PartialEq, Eq)]
pub struct MuxOpenPackage {
	pub(crate) stream_id: u32,
	pub(crate) last: bool,
	pub(crate) kind: MuxStreamKind,
	pub(crate) payload: OctetString,
	/// The optional grpc-style route (`:path`) that selects the responder's
	/// dispatch target. It is absent for a local stream whose address is
	/// already resolved, and present when a gateway must route or splice the
	/// open by servlet type.
	pub(crate) target: Option<Urn<'static>>,
	/// The relay budget, with the same contract as the unary `hops_remaining`
	/// field.
	///
	/// - The value is the number of gateway forwards the stream may still
	///   spend, and each hop decrements it.
	/// - The origin stamps the [`DEFAULT_HOP_BUDGET`] sentinel, and every
	///   gateway clamps to its own `max_hops`.
	/// - A gateway serves a `0` open locally and never re-forwards it.
	/// - DER omits the field on the common origin open.
	#[asn1(default = "default_hop_budget")]
	pub(crate) hops_remaining: u8,
}

/// The DER DEFAULT for [`MuxOpenPackage::hops_remaining`], which is the
/// origin sentinel, so unrouted and origin-routed opens omit the field.
#[cfg(feature = "transport-multiplex")]
fn default_hop_budget() -> u8 {
	DEFAULT_HOP_BUDGET
}

#[cfg(feature = "transport-multiplex")]
impl MuxOpenPackage {
	/// Build an unrouted open with the origin hop budget.
	///
	/// # Errors
	///
	/// - A DER length error when `payload` is longer than the DER length cap.
	pub fn new(stream_id: u32, last: bool, kind: MuxStreamKind, payload: impl Into<Vec<u8>>) -> DerResult<Self> {
		let payload = OctetString::new(payload)?;
		Ok(Self { stream_id, last, kind, payload, target: None, hops_remaining: DEFAULT_HOP_BUDGET })
	}

	/// Stamp a grpc-style route and relay budget on this open.
	///
	/// A `None` target with the default budget reproduces an unrouted local
	/// open, so the routed and unrouted paths share one DER shape.
	pub fn with_route(mut self, target: Option<Urn<'static>>, hops_remaining: u8) -> Self {
		self.target = target;
		self.hops_remaining = hops_remaining;
		self
	}

	/// The stream this open allocates.
	pub fn stream_id(&self) -> u32 {
		self.stream_id
	}

	/// Whether this is the initiator's final chunk on the stream.
	pub fn last(&self) -> bool {
		self.last
	}

	/// The interaction shape that the initiating call stamped on the stream.
	pub fn kind(&self) -> MuxStreamKind {
		self.kind
	}

	/// The first chunk of the initiator's payload.
	pub fn payload(&self) -> &[u8] {
		self.payload.as_bytes()
	}

	/// The grpc-style route that selects the responder's dispatch target, or
	/// `None` for an already-resolved local stream.
	pub fn target(&self) -> Option<&Urn<'static>> {
		self.target.as_ref()
	}

	/// The relay budget left on this open, which is the number of gateway
	/// forwards it may still spend. A gateway serves a `0` open locally and
	/// never re-forwards it.
	pub fn hops_remaining(&self) -> u8 {
		self.hops_remaining
	}
}

#[cfg(feature = "transport-multiplex")]
mux_chunk_package! {
	/// A continuation chunk on an open stream, in either direction.
	///
	/// See [`MuxOpenPackage`] for the stream grammar.
	MuxDataPackage,
	last: "Whether this is the sender's final chunk on the stream"
}

/// The responder trailer that ends a stream, with the status and the final
/// payload chunk inline.
///
/// A unary response whose frame fits one chunk is a single `End` record. An
/// empty payload after zero `Data` chunks means a message-less response. A
/// frame never encodes to zero bytes, so emptiness is unambiguous. See
/// [`MuxOpenPackage`] for the stream grammar.
#[cfg(feature = "transport-multiplex")]
#[derive(Sequence, Debug, Clone, PartialEq, Eq)]
pub struct MuxEndPackage {
	pub(crate) stream_id: u32,
	pub(crate) status: TransitStatus,
	pub(crate) payload: OctetString,
}

#[cfg(feature = "transport-multiplex")]
impl MuxEndPackage {
	/// Build a trailer with `status` and the final `payload` chunk.
	///
	/// # Errors
	///
	/// - A DER length error when `payload` is longer than the DER length cap.
	pub fn new(stream_id: u32, status: TransitStatus, payload: impl Into<Vec<u8>>) -> DerResult<Self> {
		let payload = OctetString::new(payload)?;
		Ok(Self { stream_id, status, payload })
	}

	/// The stream this trailer ends.
	pub fn stream_id(&self) -> u32 {
		self.stream_id
	}

	/// The status the responder reported for the stream.
	pub fn status(&self) -> TransitStatus {
		self.status
	}

	/// The final payload chunk, which is empty for a message-less response.
	pub fn payload(&self) -> &[u8] {
		self.payload.as_bytes()
	}
}

/// Grant absolute cumulative chunk credit on a stream, as QUIC
/// MAX_STREAM_DATA does ([RFC 9000 § 4.1][rfc9000-4.1]).
///
/// `limit` is the absolute total chunk count that the sender may have emitted
/// on the stream. Grants are idempotent and monotonic, so duplicated or
/// reordered grants never corrupt the flow-control ledger.
///
/// [rfc9000-4.1]: https://datatracker.ietf.org/doc/html/rfc9000#section-4.1
#[cfg(feature = "transport-multiplex")]
#[derive(Sequence, Debug, Clone, Copy, PartialEq, Eq)]
pub struct MuxCreditPackage {
	pub(crate) stream_id: u32,
	pub(crate) limit: u64,
}

#[cfg(feature = "transport-multiplex")]
impl MuxCreditPackage {
	/// A grant that raises the chunk credit on `stream_id` to `limit`.
	pub fn new(stream_id: u32, limit: u64) -> Self {
		Self { stream_id, limit }
	}

	/// The stream the grant applies to.
	pub fn stream_id(&self) -> u32 {
		self.stream_id
	}

	/// The absolute total chunk count the sender may have emitted on the
	/// stream.
	pub fn limit(&self) -> u64 {
		self.limit
	}
}

/// Cancel a single in-flight stream without tearing down the connection.
#[cfg(feature = "transport-multiplex")]
#[derive(Sequence, Debug, Clone, Copy, PartialEq, Eq)]
pub struct MuxCancelPackage {
	pub(crate) stream_id: u32,
	pub(crate) code: u32,
}

#[cfg(feature = "transport-multiplex")]
impl MuxCancelPackage {
	/// A cancel of `stream_id` for `reason`.
	pub fn new(stream_id: u32, reason: impl Into<u32>) -> Self {
		Self { stream_id, code: reason.into() }
	}

	/// The stream to cancel.
	pub fn stream_id(&self) -> u32 {
		self.stream_id
	}

	/// Why the sender cancelled the stream.
	pub fn reason(&self) -> CancelReason {
		CancelReason::from(self.code)
	}
}

/// A connection-level liveness probe ([RFC 9113 § 6.7][rfc9113-6.7]).
///
/// `opaque` is an initiator-chosen correlation value that the ack echoes
/// unchanged. Pings never allocate a stream and never reach the application
/// handler, so they keep idle connections alive through intermediaries.
///
/// [rfc9113-6.7]: https://datatracker.ietf.org/doc/html/rfc9113#section-6.7
#[cfg(feature = "transport-multiplex")]
#[derive(Sequence, Debug, Clone, Copy, PartialEq, Eq)]
pub struct MuxPingPackage {
	pub(crate) ack: bool,
	pub(crate) opaque: u64,
}

#[cfg(feature = "transport-multiplex")]
impl MuxPingPackage {
	/// A probe that carries `opaque`, or its answer when `ack` is true.
	pub fn new(ack: bool, opaque: u64) -> Self {
		Self { ack, opaque }
	}

	/// Whether this ping answers a peer probe.
	pub fn ack(&self) -> bool {
		self.ack
	}

	/// The correlation value that the probe initiator chose.
	pub fn opaque(&self) -> u64 {
		self.opaque
	}
}

/// A graceful connection shutdown.
///
/// Streams at or below `last_stream_id` drain to completion, and newer
/// streams are rejected.
#[cfg(feature = "transport-multiplex")]
#[derive(Sequence, Debug, Clone, Copy, PartialEq, Eq)]
pub struct GoAwayPackage {
	pub(crate) last_stream_id: u32,
	pub(crate) code: u32,
}

#[cfg(feature = "transport-multiplex")]
impl GoAwayPackage {
	/// A shutdown that drains the streams up to `last_stream_id`, for
	/// `reason`.
	pub fn new(last_stream_id: u32, reason: impl Into<u32>) -> Self {
		Self { last_stream_id, code: reason.into() }
	}

	/// The highest stream id that drains to completion.
	pub fn last_stream_id(&self) -> u32 {
		self.last_stream_id
	}

	/// Why the sender is shutting the connection down.
	pub fn reason(&self) -> GoAwayReason {
		GoAwayReason::from(self.code)
	}
}

/// The first rekey leg, client to server, which carries the client
/// randomness that opens an epoch renewal.
///
/// The renewal follows [RFC 9846 § 4.7.3][rfc9846-4.7.3] with an explicit
/// three-leg exchange.
///
/// [rfc9846-4.7.3]: https://datatracker.ietf.org/doc/html/rfc9846#section-4.7.3
#[cfg(feature = "transport-multiplex")]
#[derive(Sequence, Debug, Clone, PartialEq, Eq)]
pub struct MuxRekeyRequestPackage {
	pub(crate) client_random: OctetString,
}

#[cfg(feature = "transport-multiplex")]
impl MuxRekeyRequestPackage {
	/// Build a request that carries `client_random`.
	///
	/// # Errors
	///
	/// - A DER length error when `client_random` is longer than the DER length cap.
	pub fn new(client_random: impl Into<Vec<u8>>) -> DerResult<Self> {
		let client_random = OctetString::new(client_random)?;
		Ok(Self { client_random })
	}

	/// The client randomness that opens the renewal.
	pub fn client_random(&self) -> &[u8] {
		self.client_random.as_bytes()
	}
}

/// The second rekey leg, server to client, which carries the server
/// randomness and the server-signed epoch receipt.
///
/// `epoch_receipt` is DER-optional for a future keys-only renewal in the TLS
/// KeyUpdate shape ([RFC 9846 § 4.7.3][rfc9846-4.7.3]). On a budget-bearing
/// session its absence is a protocol violation, because a receipt is
/// required if and only if budgets are present.
///
/// [rfc9846-4.7.3]: https://datatracker.ietf.org/doc/html/rfc9846#section-4.7.3
#[cfg(feature = "transport-multiplex")]
#[derive(Sequence, Debug, Clone, PartialEq)]
pub struct MuxRekeyResponsePackage {
	pub(crate) server_random: OctetString,
	pub(crate) epoch_receipt: Option<Box<SignedData>>,
}

#[cfg(feature = "transport-multiplex")]
impl MuxRekeyResponsePackage {
	/// Build a response that carries `server_random` and the optional
	/// `epoch_receipt`.
	///
	/// # Errors
	///
	/// - A DER length error when `server_random` is longer than the DER length cap.
	pub fn new(server_random: impl Into<Vec<u8>>, epoch_receipt: Option<SignedData>) -> DerResult<Self> {
		let server_random = OctetString::new(server_random)?;
		Ok(Self { server_random, epoch_receipt: epoch_receipt.map(Box::new) })
	}

	/// The server randomness for the renewal.
	pub fn server_random(&self) -> &[u8] {
		self.server_random.as_bytes()
	}

	/// The server-signed epoch receipt, which a budget-bearing session
	/// requires.
	pub fn epoch_receipt(&self) -> Option<&SignedData> {
		self.epoch_receipt.as_deref()
	}
}

/// The third rekey leg, client to server, which carries the client
/// `SignerInfo` that the server appends to complete the dual-signed epoch
/// receipt.
#[cfg(feature = "transport-multiplex")]
#[derive(Sequence, Debug, Clone, PartialEq)]
pub struct MuxRekeyAckPackage {
	pub(crate) countersignature: Option<Box<SignerInfo>>,
}

#[cfg(feature = "transport-multiplex")]
impl MuxRekeyAckPackage {
	/// An acknowledgement that carries the client countersignature, if any.
	pub fn new(countersignature: Option<SignerInfo>) -> Self {
		Self { countersignature: countersignature.map(Box::new) }
	}

	/// The client `SignerInfo` that completes the dual-signed epoch receipt,
	/// present when the response carried a receipt.
	pub fn countersignature(&self) -> Option<&SignerInfo> {
		self.countersignature.as_deref()
	}
}

/// The server-to-client key-switch marker that closes a rekey exchange.
///
/// It means the server settled the epoch receipt and switched its send
/// cipher. It encodes as an empty SEQUENCE, which the derive macro cannot
/// produce, so this file implements the DER traits directly.
#[cfg(feature = "transport-multiplex")]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MuxRekeyDonePackage {}

#[cfg(feature = "transport-multiplex")]
impl EncodeValue for MuxRekeyDonePackage {
	fn value_len(&self) -> DerResult<Length> {
		Ok(Length::ZERO)
	}

	fn encode_value(&self, _writer: &mut impl Writer) -> DerResult<()> {
		Ok(())
	}
}

#[cfg(feature = "transport-multiplex")]
impl<'a> DecodeValue<'a> for MuxRekeyDonePackage {
	fn decode_value<R: Reader<'a>>(_reader: &mut R, _header: Header) -> DerResult<Self> {
		Ok(Self {})
	}
}

#[cfg(feature = "transport-multiplex")]
impl FixedTag for MuxRekeyDonePackage {
	const TAG: Tag = Tag::Sequence;
}

/// Every multiplexing message, nested under one [`TransportEnvelope`] arm.
///
/// The nesting lets the mux plane evolve with no change to the top-level
/// envelope grammar, and non-mux code never sees a mux variant.
#[cfg(feature = "transport-multiplex")]
#[derive(Choice, Clone, Debug, PartialEq)]
pub enum MuxEnvelope {
	/// Opens a stream and carries its first chunk.
	#[asn1(context_specific = "0", constructed = "true")]
	Open(MuxOpenPackage),
	/// A continuation chunk on an open stream.
	#[asn1(context_specific = "1", constructed = "true")]
	Data(MuxDataPackage),
	/// The responder trailer that ends a stream.
	#[asn1(context_specific = "2", constructed = "true")]
	End(MuxEndPackage),
	/// A grant of chunk credit on a stream.
	#[asn1(context_specific = "3", constructed = "true")]
	Credit(MuxCreditPackage),
	/// Cancels one stream and leaves the connection open.
	#[asn1(context_specific = "4", constructed = "true")]
	Cancel(MuxCancelPackage),
	/// Starts a graceful connection shutdown.
	#[asn1(context_specific = "5", constructed = "true")]
	GoAway(GoAwayPackage),
	/// A liveness probe or its answer.
	#[asn1(context_specific = "6", constructed = "true")]
	Ping(MuxPingPackage),
	/// The first rekey leg, client to server.
	#[asn1(context_specific = "7", constructed = "true")]
	RekeyRequest(MuxRekeyRequestPackage),
	/// The second rekey leg, server to client.
	#[asn1(context_specific = "8", constructed = "true")]
	RekeyResponse(MuxRekeyResponsePackage),
	/// The third rekey leg, client to server.
	#[asn1(context_specific = "9", constructed = "true")]
	RekeyAck(MuxRekeyAckPackage),
	/// The server marker that closes a rekey exchange.
	#[asn1(context_specific = "10", constructed = "true")]
	RekeyDone(MuxRekeyDonePackage),
}

/// The transport envelope that wraps every message at the transport layer.
///
/// The transport handles it internally, so it stays transparent to users.
#[derive(Beamable, Choice, Clone, Debug, PartialEq)]
pub enum TransportEnvelope {
	/// A single-flight request.
	#[asn1(context_specific = "0", constructed = "true")]
	Request(RequestPackage),
	/// The response to a single-flight request.
	#[asn1(context_specific = "1", constructed = "true")]
	Response(ResponsePackage),
	/// A key-transport handshake container, kept with the bytes that
	/// carried it.
	#[cfg(feature = "x509")]
	#[asn1(context_specific = "2", constructed = "true")]
	EnvelopedData(Box<WireDer<EnvelopedData>>),
	/// A signed handshake container, kept with the bytes that carried it.
	#[cfg(feature = "x509")]
	#[asn1(context_specific = "3", constructed = "true")]
	SignedData(Box<WireDer<SignedData>>),
	/// A multiplexing message.
	#[cfg(feature = "transport-multiplex")]
	#[asn1(context_specific = "4", constructed = "true")]
	Mux(MuxEnvelope),
}

/// The outermost envelope, in cleartext or in encrypted form.
#[derive(Choice, Clone, Debug, PartialEq)]
pub enum WireEnvelope {
	/// A transport envelope sent without encryption, as handshake containers
	/// and cleartext endpoints send it.
	#[asn1(context_specific = "0", constructed = "true")]
	Cleartext(TransportEnvelope),
	/// A transport envelope sealed under the session's send cipher.
	#[asn1(context_specific = "1", constructed = "true")]
	Encrypted(EncryptedContentInfo),
}

/// Whether an envelope goes out as cleartext or as encrypted bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireMode {
	/// Emit raw `TransportEnvelope` bytes.
	Cleartext,
	/// Encrypt the encoded envelope before emission.
	Encrypted,
}

impl From<ResponsePackage> for TransportEnvelope {
	fn from(pkg: ResponsePackage) -> Self {
		Self::Response(pkg)
	}
}

impl From<Frame> for TransportEnvelope {
	fn from(msg: Frame) -> Self {
		Self::Request(RequestPackage { message: Arc::new(msg) })
	}
}

#[cfg(feature = "transport-multiplex")]
impl From<MuxEnvelope> for TransportEnvelope {
	fn from(envelope: MuxEnvelope) -> Self {
		Self::Mux(envelope)
	}
}

#[cfg(feature = "transport-multiplex")]
macro_rules! impl_mux_envelope_from {
	($($package:ty => $variant:ident),+ $(,)?) => {
		$(
			impl From<$package> for MuxEnvelope {
				fn from(pkg: $package) -> Self {
					Self::$variant(pkg)
				}
			}

			impl From<$package> for TransportEnvelope {
				fn from(pkg: $package) -> Self {
					Self::Mux(MuxEnvelope::$variant(pkg))
				}
			}
		)+
	};
}

#[cfg(feature = "transport-multiplex")]
impl_mux_envelope_from! {
	MuxOpenPackage => Open,
	MuxDataPackage => Data,
	MuxEndPackage => End,
	MuxCreditPackage => Credit,
	MuxCancelPackage => Cancel,
	GoAwayPackage => GoAway,
	MuxPingPackage => Ping,
	MuxRekeyRequestPackage => RekeyRequest,
	MuxRekeyResponsePackage => RekeyResponse,
	MuxRekeyAckPackage => RekeyAck,
	MuxRekeyDonePackage => RekeyDone,
}

impl TransportEnvelope {
	/// Create a request envelope that carries `msg`.
	pub fn new_request(msg: Frame) -> Self {
		Self::Request(RequestPackage { message: Arc::new(msg) })
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::testing::TestFrame;
	use std::error::Error;

	struct PackageTestCase {
		message_value: &'static str,
		expected_status: TransitStatus,
		should_have_message: bool,
	}

	impl PackageTestCase {
		fn create_request(&self) -> RequestPackage {
			RequestPackage::new(TestFrame::v0(Some(self.message_value), None))
		}

		fn create_response(&self) -> ResponsePackage {
			ResponsePackage {
				status: self.expected_status,
				message: if self.should_have_message {
					Some(Arc::new(TestFrame::v0(Some(self.message_value), None)))
				} else {
					None
				},
			}
		}
	}

	fn as_test_cases() -> Vec<PackageTestCase> {
		vec![
			PackageTestCase {
				message_value: "Hi",
				expected_status: TransitStatus::Ok,
				should_have_message: true,
			},
			PackageTestCase {
				// cspell:disable-next-line
				message_value: "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.",
				expected_status: TransitStatus::Ok,
				should_have_message: true,
			},
			PackageTestCase {
				message_value: "",
				expected_status: TransitStatus::Ok,
				should_have_message: true,
			},
			PackageTestCase {
				message_value: "ResourceExhausted",
				expected_status: TransitStatus::ResourceExhausted,
				should_have_message: false,
			},
			PackageTestCase {
				message_value: "Unauthenticated",
				expected_status: TransitStatus::Unauthenticated,
				should_have_message: false,
			},
			PackageTestCase {
				message_value: "NotFound",
				expected_status: TransitStatus::NotFound,
				should_have_message: false,
			},
		]
	}

	#[test]
	fn test_request_package_encode_decode() -> Result<(), Box<dyn Error>> {
		for test_case in as_test_cases() {
			let original = test_case.create_request();
			let encoded = original.to_der()?;
			let decoded = RequestPackage::from_der(&encoded)?;
			assert_eq!(original, decoded);
		}

		Ok(())
	}

	#[test]
	fn test_response_package_encode_decode() -> Result<(), Box<dyn Error>> {
		for test_case in as_test_cases() {
			let original = test_case.create_response();
			let encoded = original.to_der()?;
			let decoded = ResponsePackage::from_der(&encoded)?;
			assert_eq!(original.status, decoded.status);
			assert_eq!(original.message, decoded.message);
		}

		Ok(())
	}

	#[test]
	fn test_length_validation_request() -> Result<(), Box<dyn Error>> {
		let original = RequestPackage::new(TestFrame::v0(None, None));
		let mut encoded = original.to_der()?;

		// Corrupt one byte after encoding. The length is encoded as a Uint at
		// the start of the sequence.
		if encoded.len() > 10 {
			let corrupt_pos = 5;
			encoded[corrupt_pos] = encoded[corrupt_pos].wrapping_add(1);

			// The length mismatch must fail the decode.
			let result = RequestPackage::from_der(&encoded);
			assert!(result.is_err(), "Should fail with corrupted length");
		}

		Ok(())
	}

	#[test]
	fn test_length_validation_response() -> Result<(), Box<dyn Error>> {
		let original =
			ResponsePackage { status: TransitStatus::Ok, message: Some(Arc::new(TestFrame::v0(None, None))) };

		// Corrupt one byte of the length field.
		let mut encoded = original.to_der()?;
		if encoded.len() > 10 {
			let corrupt_pos = 8;
			encoded[corrupt_pos] = encoded[corrupt_pos].wrapping_add(1);

			// The length mismatch must fail the decode.
			let result = ResponsePackage::from_der(&encoded);
			assert!(result.is_err(), "Should fail with corrupted length");
		}

		Ok(())
	}

	#[test]
	fn test_response_empty_message() -> Result<(), Box<dyn Error>> {
		let original = ResponsePackage { status: TransitStatus::ResourceExhausted, message: None };

		let encoded = original.to_der()?;
		let decoded = ResponsePackage::from_der(&encoded)?;
		assert_eq!(original.status, decoded.status);
		assert_eq!(original.message, decoded.message);
		Ok(())
	}

	#[cfg(feature = "transport-multiplex")]
	fn frame_payload(label: impl AsRef<str>) -> Result<Vec<u8>, Box<dyn Error>> {
		let label = label.as_ref();
		let payload = TestFrame::v0(Some(label), None).to_der()?;
		Ok(payload)
	}

	/// Reason accessors derive from the encoded code field, so struct
	/// equality covers them.
	#[cfg(feature = "transport-multiplex")]
	fn assert_round_trip<T>(cases: impl IntoIterator<Item = T>) -> Result<(), Box<dyn Error>>
	where
		T: Encode + for<'a> Decode<'a> + PartialEq + core::fmt::Debug,
	{
		for original in cases {
			let encoded = original.to_der()?;
			let decoded = T::from_der(&encoded)?;
			assert_eq!(original, decoded);
		}

		Ok(())
	}

	#[cfg(feature = "transport-multiplex")]
	#[test]
	fn test_mux_open_package_encode_decode() -> Result<(), Box<dyn Error>> {
		assert_round_trip([
			MuxOpenPackage::new(1, true, MuxStreamKind::Unary, frame_payload("open-unary")?)?,
			MuxOpenPackage::new(3, false, MuxStreamKind::Streaming, frame_payload("open-chunked")?)?,
			MuxOpenPackage::new(5, false, MuxStreamKind::Duplex, frame_payload("open-duplex")?)?,
			MuxOpenPackage::new(u32::MAX, false, MuxStreamKind::Unary, Vec::new())?,
		])
	}

	// The kind is the dispatch discriminator, so every variant must survive
	// encoding unchanged.
	#[cfg(feature = "transport-multiplex")]
	#[test]
	fn test_mux_open_package_kind_round_trips_every_variant() -> Result<(), Box<dyn Error>> {
		let kinds = [MuxStreamKind::Unary, MuxStreamKind::Streaming, MuxStreamKind::Duplex];
		for kind in kinds {
			let package = MuxOpenPackage::new(7, false, kind, vec![1u8; 4])?;
			let decoded = MuxOpenPackage::from_der(&package.to_der()?)?;
			assert_eq!(decoded.kind(), kind);
		}

		Ok(())
	}

	// An unrouted open carries no target and the origin budget, and the
	// grpc-style route with a spent budget survives encoding.
	#[cfg(feature = "transport-multiplex")]
	#[test]
	fn test_mux_open_package_route_round_trips() -> Result<(), Box<dyn Error>> {
		let target = crate::urn!("tb", "servlet:ledger");

		let unrouted = MuxOpenPackage::new(9, false, MuxStreamKind::Streaming, frame_payload("open-local")?)?;
		assert_eq!(unrouted.target(), None);
		assert_eq!(unrouted.hops_remaining(), DEFAULT_HOP_BUDGET);

		let routed = unrouted.clone().with_route(Some(target.clone()), 0);
		let decoded = MuxOpenPackage::from_der(&routed.to_der()?)?;
		assert_eq!(decoded.target(), Some(&target));
		assert_eq!(decoded.hops_remaining(), 0);

		Ok(())
	}

	// A default open must encode to the exact bytes of the unrouted shape.
	// The DER-optional target and the DEFAULT-budget hops add nothing, so
	// existing peers decode it unchanged.
	#[cfg(feature = "transport-multiplex")]
	#[test]
	fn test_mux_open_package_unrouted_is_wire_stable() -> Result<(), Box<dyn Error>> {
		let package = MuxOpenPackage::new(11, true, MuxStreamKind::Unary, frame_payload("open-stable")?)?;
		let encoded = package.to_der()?;
		let decoded = MuxOpenPackage::from_der(&encoded)?;
		assert_eq!(decoded, package);
		assert_eq!(decoded.target(), None);
		assert_eq!(decoded.hops_remaining(), DEFAULT_HOP_BUDGET);
		assert_eq!(decoded.to_der()?, encoded);

		Ok(())
	}

	#[cfg(feature = "transport-multiplex")]
	#[test]
	fn test_mux_data_package_encode_decode() -> Result<(), Box<dyn Error>> {
		assert_round_trip([
			MuxDataPackage::new(1, false, vec![0xAB; 64])?,
			MuxDataPackage::new(1, true, vec![0xCD])?,
			MuxDataPackage::new(u32::MAX, true, Vec::new())?,
		])
	}

	#[cfg(feature = "transport-multiplex")]
	#[test]
	fn test_mux_end_package_encode_decode() -> Result<(), Box<dyn Error>> {
		assert_round_trip([
			MuxEndPackage::new(1, TransitStatus::Ok, frame_payload("end-unary")?)?,
			MuxEndPackage::new(3, TransitStatus::ResourceExhausted, Vec::new())?,
			MuxEndPackage::new(u32::MAX, TransitStatus::Unauthenticated, Vec::new())?,
		])
	}

	#[cfg(feature = "transport-multiplex")]
	#[test]
	fn test_mux_credit_package_encode_decode() -> Result<(), Box<dyn Error>> {
		assert_round_trip([
			MuxCreditPackage::new(1, 0),
			MuxCreditPackage::new(3, 4096),
			MuxCreditPackage::new(u32::MAX, u64::MAX),
		])
	}

	#[cfg(feature = "transport-multiplex")]
	#[test]
	fn test_mux_cancel_package_encode_decode() -> Result<(), Box<dyn Error>> {
		assert_round_trip([
			MuxCancelPackage::new(1, CancelReason::Cancelled),
			MuxCancelPackage::new(3, CancelReason::Timeout),
			MuxCancelPackage::new(5, CancelReason::Application(MUX_APPLICATION_CODE_FLOOR + 7)),
			MuxCancelPackage::new(u32::MAX, CancelReason::Rejected),
		])
	}

	#[cfg(feature = "transport-multiplex")]
	#[test]
	fn test_mux_ping_package_encode_decode() -> Result<(), Box<dyn Error>> {
		assert_round_trip([
			MuxPingPackage::new(false, 0),
			MuxPingPackage::new(true, 1),
			MuxPingPackage::new(false, u64::MAX),
		])
	}

	/// A structurally valid `SignerInfo` for encoding round trips. The
	/// signature bytes are arbitrary, because envelope tests exercise encoding
	/// and skip verification.
	#[cfg(feature = "transport-multiplex")]
	fn sample_signer_info() -> Result<SignerInfo, Box<dyn Error>> {
		use crate::cms::cert::x509::ext::pkix::SubjectKeyIdentifier;
		use crate::cms::signed_data::SignerIdentifier;
		use crate::crypto::sign::SignerInfoExt;
		use crate::oids::{HASH_SHA3_256, SIGNER_ECDSA_WITH_SHA3_256};
		use crate::spki::AlgorithmIdentifierOwned;

		let skid_octet = OctetString::new([0xAB; 20])?;
		let skid = SubjectKeyIdentifier::from(skid_octet);
		let signer = SignerInfo::from_parts(
			[0xCD; 64],
			AlgorithmIdentifierOwned { oid: SIGNER_ECDSA_WITH_SHA3_256, parameters: None },
			AlgorithmIdentifierOwned { oid: HASH_SHA3_256, parameters: None },
			SignerIdentifier::SubjectKeyIdentifier(skid),
		)?;
		Ok(signer)
	}

	/// A structurally valid single-signer `SignedData` for encoding round
	/// trips.
	#[cfg(feature = "transport-multiplex")]
	fn sample_signed_data() -> Result<SignedData, Box<dyn Error>> {
		use crate::cms::content_info::CmsVersion;
		use crate::cms::signed_data::{EncapsulatedContentInfo, SignerInfos};
		use crate::der::asn1::SetOfVec;
		use crate::der::Any;
		use crate::oids::{HASH_SHA3_256, SESSION_RECEIPT_CONTENT};
		use crate::spki::AlgorithmIdentifierOwned;

		let body_der = OctetString::new(b"epoch-receipt-body".as_slice())?.to_der()?;
		let econtent = Any::from_der(&body_der)?;
		let algorithm_identifier = AlgorithmIdentifierOwned { oid: HASH_SHA3_256, parameters: None };
		let digest_algorithms = SetOfVec::try_from(vec![algorithm_identifier])?;
		let signer_infos = SignerInfos(SetOfVec::try_from(vec![sample_signer_info()?])?);

		let artifact = SignedData {
			version: CmsVersion::V3,
			digest_algorithms,
			encap_content_info: EncapsulatedContentInfo {
				econtent_type: SESSION_RECEIPT_CONTENT,
				econtent: Some(econtent),
			},
			certificates: None,
			crls: None,
			signer_infos,
		};
		Ok(artifact)
	}

	#[cfg(feature = "transport-multiplex")]
	#[test]
	fn test_mux_rekey_request_package_encode_decode() -> Result<(), Box<dyn Error>> {
		assert_round_trip([
			MuxRekeyRequestPackage::new([0u8; 32])?,
			MuxRekeyRequestPackage::new([0xFF; 32])?,
			MuxRekeyRequestPackage::new(Vec::new())?,
		])
	}

	#[cfg(feature = "transport-multiplex")]
	#[test]
	fn test_mux_rekey_response_package_encode_decode() -> Result<(), Box<dyn Error>> {
		assert_round_trip([
			MuxRekeyResponsePackage::new([7u8; 32], Some(sample_signed_data()?))?,
			MuxRekeyResponsePackage::new([9u8; 32], None)?,
		])
	}

	#[cfg(feature = "transport-multiplex")]
	#[test]
	fn test_mux_rekey_ack_package_encode_decode() -> Result<(), Box<dyn Error>> {
		assert_round_trip([
			MuxRekeyAckPackage::new(Some(sample_signer_info()?)),
			MuxRekeyAckPackage::new(None),
		])
	}

	#[cfg(feature = "transport-multiplex")]
	#[test]
	fn test_mux_rekey_done_package_encode_decode() -> Result<(), Box<dyn Error>> {
		assert_round_trip([MuxRekeyDonePackage::default()])
	}

	#[cfg(feature = "transport-multiplex")]
	#[test]
	fn test_go_away_package_encode_decode() -> Result<(), Box<dyn Error>> {
		assert_round_trip([
			GoAwayPackage::new(0, GoAwayReason::Shutdown),
			GoAwayPackage::new(7, GoAwayReason::ProtocolError),
			GoAwayPackage::new(9, GoAwayReason::EnhanceYourCalm),
			GoAwayPackage::new(11, GoAwayReason::Application(MUX_APPLICATION_CODE_FLOOR)),
			GoAwayPackage::new(13, GoAwayReason::BudgetExhausted),
			GoAwayPackage::new(15, GoAwayReason::SettlementFailed),
			GoAwayPackage::new(u32::MAX, GoAwayReason::Shutdown),
		])
	}

	#[cfg(feature = "transport-multiplex")]
	#[test]
	fn test_go_away_reason_labels() {
		let cases = [
			(GoAwayReason::Shutdown, "shutdown"),
			(GoAwayReason::ProtocolError, "protocol-error"),
			(GoAwayReason::EnhanceYourCalm, "enhance-your-calm"),
			(GoAwayReason::BudgetExhausted, "budget-exhausted"),
			(GoAwayReason::SettlementFailed, "settlement-failed"),
			(GoAwayReason::Application(MUX_APPLICATION_CODE_FLOOR), "application"),
		];
		for (reason, label) in cases {
			assert_eq!(reason.as_str(), label);
		}
	}

	#[cfg(feature = "transport-multiplex")]
	#[test]
	fn test_cancel_reason_code_space_round_trip() {
		let known = [
			(0u32, CancelReason::Cancelled),
			(1, CancelReason::Timeout),
			(2, CancelReason::Rejected),
		];
		for (code, reason) in known {
			assert_eq!(CancelReason::from(code), reason);
			assert_eq!(u32::from(reason), code);
		}

		let app_code = MUX_APPLICATION_CODE_FLOOR + 42;
		assert_eq!(CancelReason::from(app_code), CancelReason::Application(app_code));
		assert_eq!(u32::from(CancelReason::Application(app_code)), app_code);
	}

	#[cfg(feature = "transport-multiplex")]
	#[test]
	fn test_go_away_reason_code_space_round_trip() {
		let known = [
			(0u32, GoAwayReason::Shutdown),
			(1, GoAwayReason::ProtocolError),
			(2, GoAwayReason::EnhanceYourCalm),
			(3, GoAwayReason::BudgetExhausted),
			(4, GoAwayReason::SettlementFailed),
		];
		for (code, reason) in known {
			assert_eq!(GoAwayReason::from(code), reason);
			assert_eq!(u32::from(reason), code);
		}

		let app_code = MUX_APPLICATION_CODE_FLOOR + 42;
		assert_eq!(GoAwayReason::from(app_code), GoAwayReason::Application(app_code));
		assert_eq!(u32::from(GoAwayReason::Application(app_code)), app_code);
	}

	#[cfg(feature = "transport-multiplex")]
	#[test]
	fn test_unknown_reserved_code_decodes_as_application() {
		let reserved_unknown = 0x0FFFu32;
		assert_eq!(
			CancelReason::from(reserved_unknown),
			CancelReason::Application(reserved_unknown)
		);
		assert_eq!(
			GoAwayReason::from(reserved_unknown),
			GoAwayReason::Application(reserved_unknown)
		);
	}

	#[cfg(feature = "transport-multiplex")]
	#[test]
	fn test_mux_envelope_variants_round_trip() -> Result<(), Box<dyn Error>> {
		assert_round_trip([
			TransportEnvelope::from(MuxOpenPackage::new(1, true, MuxStreamKind::Unary, frame_payload("mux-open")?)?),
			TransportEnvelope::from(MuxDataPackage::new(1, false, vec![0xEF; 16])?),
			TransportEnvelope::from(MuxEndPackage::new(1, TransitStatus::Ok, frame_payload("mux-end")?)?),
			TransportEnvelope::from(MuxCreditPackage::new(1, 128)),
			TransportEnvelope::from(MuxCancelPackage::new(5, CancelReason::Cancelled)),
			TransportEnvelope::from(GoAwayPackage::new(3, GoAwayReason::Shutdown)),
			TransportEnvelope::from(MuxPingPackage::new(false, 7)),
			{
				let rekey_request = MuxRekeyRequestPackage::new([1u8; 32])?;
				TransportEnvelope::from(rekey_request)
			},
			{
				let signed = sample_signed_data()?;
				let rekey_response = MuxRekeyResponsePackage::new([2u8; 32], Some(signed))?;
				TransportEnvelope::from(rekey_response)
			},
			{
				let signer = sample_signer_info()?;
				TransportEnvelope::from(MuxRekeyAckPackage::new(Some(signer)))
			},
			TransportEnvelope::from(MuxRekeyDonePackage::default()),
		])
	}
}
