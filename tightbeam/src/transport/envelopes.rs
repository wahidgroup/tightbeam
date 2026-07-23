//! Wire protocol data structures for transport layer envelopes

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

#[cfg(feature = "transport-multiplex")]
use crate::der::asn1::OctetString;
#[cfg(feature = "transport-multiplex")]
use crate::der::Sequence;

#[cfg(feature = "x509")]
mod x509 {
	pub use crate::cms::enveloped_data::EnvelopedData;
	pub use crate::cms::signed_data::SignedData;
}

#[cfg(feature = "derive")]
use crate::Beamable;
#[cfg(not(feature = "derive"))]
use crate::{Message, Version};
#[cfg(feature = "x509")]
use x509::*;

/// Request package containing the message frame
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestPackage {
	pub(crate) message: Arc<Frame>,
}

impl RequestPackage {
	pub fn new(message: Frame) -> Self {
		Self { message: Arc::new(message) }
	}

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

/// Response package containing status and optional message
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ResponsePackage {
	pub(crate) status: TransitStatus,
	pub(crate) message: Option<Arc<Frame>>,
}

impl ResponsePackage {
	pub fn new(status: TransitStatus, message: Option<Frame>) -> Self {
		Self { status, message: message.map(Arc::new) }
	}

	pub fn status(&self) -> TransitStatus {
		self.status
	}

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

/// First u32 code owned by applications in the multiplexing reason-code
/// space. Codes below the floor are reserved for the TightBeam protocol
/// (HTTP/2 error-code and QUIC application-close precedent:
/// RFC 9113 § 7, RFC 9000 § 20.2).
#[cfg(feature = "transport-multiplex")]
pub const MUX_APPLICATION_CODE_FLOOR: u32 = 0x1000;

/// Reason a single stream was cancelled (RFC 9113 § 6.4 analog).
///
/// Open u32 code space: TB-reserved codes decode to named variants,
/// everything else round-trips through [`CancelReason::Application`] so
/// unknown codes never kill a connection. `Application(code)` with a
/// TB-reserved `code` canonicalizes to the named variant on decode.
#[cfg(feature = "transport-multiplex")]
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
pub enum CancelReason {
	/// Requester is no longer interested in the response
	#[default]
	Cancelled,
	/// Per-stream deadline elapsed before a response arrived
	Timeout,
	/// Responder refused to process the stream
	Rejected,
	/// Application-defined code (at or above
	/// [`MUX_APPLICATION_CODE_FLOOR`]) or a TB code this build predates
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

/// Reason the connection is shutting down (RFC 9113 § 6.8 analog).
///
/// Same open u32 code space rules as [`CancelReason`].
#[cfg(feature = "transport-multiplex")]
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
pub enum GoAwayReason {
	/// Orderly shutdown initiated by the sender
	#[default]
	Shutdown,
	/// Peer violated the multiplexing protocol
	ProtocolError,
	/// Peer exceeded the cancel budget (RFC 9113 § 7
	/// ENHANCE_YOUR_CALM analog, CVE-2023-44487 hardening)
	EnhanceYourCalm,
	/// Application-defined code (at or above
	/// [`MUX_APPLICATION_CODE_FLOOR`]) or a TB code this build predates
	Application(u32),
}

#[cfg(feature = "transport-multiplex")]
impl From<GoAwayReason> for u32 {
	fn from(reason: GoAwayReason) -> u32 {
		match reason {
			GoAwayReason::Shutdown => 0,
			GoAwayReason::ProtocolError => 1,
			GoAwayReason::EnhanceYourCalm => 2,
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
			code => Self::Application(code),
		}
	}
}

/// Chunk-bearing stream packages share one wire shape. Only the CHOICE
/// tag on [`MuxEnvelope`] distinguishes them.
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
			/// # Errors
			/// `payload` longer than the DER length cap
			pub fn new(stream_id: u32, last: bool, payload: impl Into<Vec<u8>>) -> DerResult<Self> {
				let payload = OctetString::new(payload)?;
				Ok(Self { stream_id, last, payload })
			}

			pub fn stream_id(&self) -> u32 {
				self.stream_id
			}

			#[doc = $last_doc]
			pub fn last(&self) -> bool {
				self.last
			}

			pub fn payload(&self) -> &[u8] {
				self.payload.as_bytes()
			}
		}
	};
}

#[cfg(feature = "transport-multiplex")]
mux_chunk_package! {
	/// Open a stream and carry its first payload chunk inline.
	///
	/// One unified stream grammar (RFC 9113 § 8.1 analog, request = stream):
	///
	/// ```text
	/// initiator:  Open(last?)   Data(...)*  Data(last)
	/// responder:  Data(...)*    End(status, payload?)
	/// either:     Cancel(code)  Credit(limit)
	/// ```
	///
	/// A unary request whose frame fits one chunk is a single
	/// `Open(last = true)` record. Chunks concatenate in arrival order into
	/// the message frame DER. The ordered AEAD channel with strict counter
	/// sequencing already proves order and completeness, so chunks carry no
	/// sequence numbers. Stream correlation metadata travels inside the
	/// encrypted envelope payload, so concurrency patterns never leak
	/// outside the AEAD.
	MuxOpenPackage,
	last: "Whether this is the initiator's final chunk on the stream"
}

#[cfg(feature = "transport-multiplex")]
mux_chunk_package! {
	/// Continuation chunk on an open stream, either direction.
	///
	/// See [`MuxOpenPackage`] for the stream grammar.
	MuxDataPackage,
	last: "Whether this is the sender's final chunk on the stream"
}

/// Responder trailer ending a stream: status plus the final payload
/// chunk inline.
///
/// A unary response whose frame fits one chunk is a single `End` record.
/// An empty payload after zero `Data` chunks means a message-less
/// response (a frame never encodes to zero bytes, so emptiness is
/// unambiguous). See [`MuxOpenPackage`] for the stream grammar.
#[cfg(feature = "transport-multiplex")]
#[derive(Sequence, Debug, Clone, PartialEq, Eq)]
pub struct MuxEndPackage {
	pub(crate) stream_id: u32,
	pub(crate) status: TransitStatus,
	pub(crate) payload: OctetString,
}

#[cfg(feature = "transport-multiplex")]
impl MuxEndPackage {
	/// # Errors
	/// `payload` longer than the DER length cap
	pub fn new(stream_id: u32, status: TransitStatus, payload: impl Into<Vec<u8>>) -> DerResult<Self> {
		let payload = OctetString::new(payload)?;
		Ok(Self { stream_id, status, payload })
	}

	pub fn stream_id(&self) -> u32 {
		self.stream_id
	}

	pub fn status(&self) -> TransitStatus {
		self.status
	}

	pub fn payload(&self) -> &[u8] {
		self.payload.as_bytes()
	}
}

/// Grant absolute cumulative chunk credit on a stream (QUIC
/// MAX_STREAM_DATA analog, RFC 9000 § 4.1).
///
/// `limit` is the total chunk count the sender may have emitted on the
/// stream, not a delta. Grants are idempotent and monotonic, so
/// duplicated or reordered grants never corrupt the flow-control ledger.
#[cfg(feature = "transport-multiplex")]
#[derive(Sequence, Debug, Clone, Copy, PartialEq, Eq)]
pub struct MuxCreditPackage {
	pub(crate) stream_id: u32,
	pub(crate) limit: u64,
}

#[cfg(feature = "transport-multiplex")]
impl MuxCreditPackage {
	pub fn new(stream_id: u32, limit: u64) -> Self {
		Self { stream_id, limit }
	}

	pub fn stream_id(&self) -> u32 {
		self.stream_id
	}

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
	pub fn new(stream_id: u32, reason: impl Into<u32>) -> Self {
		Self { stream_id, code: reason.into() }
	}

	pub fn stream_id(&self) -> u32 {
		self.stream_id
	}

	pub fn reason(&self) -> CancelReason {
		CancelReason::from(self.code)
	}
}

/// Connection-level liveness probe
/// ([RFC 9113 § 6.7](https://datatracker.ietf.org/doc/html/rfc9113#section-6.7) analog).
///
/// `opaque` is an initiator-chosen correlation value echoed unchanged in
/// the ack. Pings never allocate a stream and never reach the application
/// handler, so they keep idle connections alive through intermediaries.
#[cfg(feature = "transport-multiplex")]
#[derive(Sequence, Debug, Clone, Copy, PartialEq, Eq)]
pub struct MuxPingPackage {
	pub(crate) ack: bool,
	pub(crate) opaque: u64,
}

#[cfg(feature = "transport-multiplex")]
impl MuxPingPackage {
	pub fn new(ack: bool, opaque: u64) -> Self {
		Self { ack, opaque }
	}

	/// Whether this ping answers a peer probe
	pub fn ack(&self) -> bool {
		self.ack
	}

	/// Correlation value chosen by the probe initiator
	pub fn opaque(&self) -> u64 {
		self.opaque
	}
}

/// Graceful connection shutdown: streams at or below `last_stream_id`
/// drain to completion, newer ones are rejected.
#[cfg(feature = "transport-multiplex")]
#[derive(Sequence, Debug, Clone, Copy, PartialEq, Eq)]
pub struct GoAwayPackage {
	pub(crate) last_stream_id: u32,
	pub(crate) code: u32,
}

#[cfg(feature = "transport-multiplex")]
impl GoAwayPackage {
	pub fn new(last_stream_id: u32, reason: impl Into<u32>) -> Self {
		Self { last_stream_id, code: reason.into() }
	}

	pub fn last_stream_id(&self) -> u32 {
		self.last_stream_id
	}

	pub fn reason(&self) -> GoAwayReason {
		GoAwayReason::from(self.code)
	}
}

/// Every multiplexing message, nested under one [`TransportEnvelope`]
/// arm so the mux plane evolves without touching the top-level envelope
/// grammar and non-mux code never sees mux variants.
#[cfg(feature = "transport-multiplex")]
#[derive(Choice, Clone, Debug, PartialEq, Eq)]
pub enum MuxEnvelope {
	#[asn1(context_specific = "0", constructed = "true")]
	Open(MuxOpenPackage),
	#[asn1(context_specific = "1", constructed = "true")]
	Data(MuxDataPackage),
	#[asn1(context_specific = "2", constructed = "true")]
	End(MuxEndPackage),
	#[asn1(context_specific = "3", constructed = "true")]
	Credit(MuxCreditPackage),
	#[asn1(context_specific = "4", constructed = "true")]
	Cancel(MuxCancelPackage),
	#[asn1(context_specific = "5", constructed = "true")]
	GoAway(GoAwayPackage),
	#[asn1(context_specific = "6", constructed = "true")]
	Ping(MuxPingPackage),
}

/// Transport envelope wrapping all messages at the transport layer.
/// This is transparent to users and handled internally.
#[cfg_attr(feature = "derive", derive(Beamable))]
#[derive(Choice, Clone, Debug, PartialEq)]
pub enum TransportEnvelope {
	#[asn1(context_specific = "0", constructed = "true")]
	Request(RequestPackage),
	#[asn1(context_specific = "1", constructed = "true")]
	Response(ResponsePackage),
	#[cfg(feature = "x509")]
	#[asn1(context_specific = "2", constructed = "true")]
	EnvelopedData(Box<EnvelopedData>),
	#[cfg(feature = "x509")]
	#[asn1(context_specific = "3", constructed = "true")]
	SignedData(Box<SignedData>),
	#[cfg(feature = "transport-multiplex")]
	#[asn1(context_specific = "4", constructed = "true")]
	Mux(MuxEnvelope),
}

/// Wire-level envelope that can be either cleartext or encrypted
#[derive(Choice, Clone, Debug, PartialEq)]
pub enum WireEnvelope {
	#[asn1(context_specific = "0", constructed = "true")]
	Cleartext(TransportEnvelope),
	#[asn1(context_specific = "1", constructed = "true")]
	Encrypted(EncryptedContentInfo),
}

/// Determines whether an envelope should be emitted as cleartext or encrypted bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireMode {
	/// Emit raw `TransportEnvelope` bytes.
	Cleartext,
	/// Encrypt the encoded envelope prior to emission.
	Encrypted,
}

#[cfg(not(feature = "derive"))]
impl Message for TransportEnvelope {
	const MUST_BE_NON_REPUDIABLE: bool = false;
	const MUST_BE_CONFIDENTIAL: bool = false;
	const MUST_BE_COMPRESSED: bool = false;
	const MUST_BE_PRIORITIZED: bool = false;
	const MIN_VERSION: Version = Version::V0;
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
}

impl TransportEnvelope {
	/// Create a new request envelope from a message
	pub fn new_request(msg: Frame) -> Self {
		Self::Request(RequestPackage { message: Arc::new(msg) })
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::testing::create_v0_tightbeam;
	use std::error::Error;

	struct PackageTestCase {
		message_value: &'static str,
		expected_status: TransitStatus,
		should_have_message: bool,
	}

	impl PackageTestCase {
		fn create_request(&self) -> RequestPackage {
			RequestPackage::new(create_v0_tightbeam(Some(self.message_value), None))
		}

		fn create_response(&self) -> ResponsePackage {
			ResponsePackage {
				status: self.expected_status,
				message: if self.should_have_message {
					Some(Arc::new(create_v0_tightbeam(Some(self.message_value), None)))
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
		let original = RequestPackage::new(create_v0_tightbeam(None, None));
		let mut encoded = original.to_der()?;

		// Corrupt the length field by manipulating bytes after encoding
		// The length is encoded as a Uint at the beginning of the sequence
		if encoded.len() > 10 {
			// Corrupt a byte in the middle to simulate wrong length
			let corrupt_pos = 5;
			encoded[corrupt_pos] = encoded[corrupt_pos].wrapping_add(1);

			// Decoding should fail due to length mismatch
			let result = RequestPackage::from_der(&encoded);
			assert!(result.is_err(), "Should fail with corrupted length");
		}

		Ok(())
	}

	#[test]
	fn test_length_validation_response() -> Result<(), Box<dyn Error>> {
		let original = ResponsePackage {
			status: TransitStatus::Ok,
			message: Some(Arc::new(create_v0_tightbeam(None, None))),
		};

		// Corrupt the length field
		let mut encoded = original.to_der()?;
		if encoded.len() > 10 {
			let corrupt_pos = 8;
			encoded[corrupt_pos] = encoded[corrupt_pos].wrapping_add(1);

			// Decoding should fail due to length mismatch
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
	fn frame_payload(label: &str) -> Result<Vec<u8>, Box<dyn Error>> {
		let payload = create_v0_tightbeam(Some(label), None).to_der()?;
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
			MuxOpenPackage::new(1, true, frame_payload("open-unary")?)?,
			MuxOpenPackage::new(3, false, frame_payload("open-chunked")?)?,
			MuxOpenPackage::new(u32::MAX, false, Vec::new())?,
		])
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

	#[cfg(feature = "transport-multiplex")]
	#[test]
	fn test_go_away_package_encode_decode() -> Result<(), Box<dyn Error>> {
		assert_round_trip([
			GoAwayPackage::new(0, GoAwayReason::Shutdown),
			GoAwayPackage::new(7, GoAwayReason::ProtocolError),
			GoAwayPackage::new(9, GoAwayReason::EnhanceYourCalm),
			GoAwayPackage::new(11, GoAwayReason::Application(MUX_APPLICATION_CODE_FLOOR)),
			GoAwayPackage::new(u32::MAX, GoAwayReason::Shutdown),
		])
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
			TransportEnvelope::from(MuxOpenPackage::new(1, true, frame_payload("mux-open")?)?),
			TransportEnvelope::from(MuxDataPackage::new(1, false, vec![0xEF; 16])?),
			TransportEnvelope::from(MuxEndPackage::new(1, TransitStatus::Ok, frame_payload("mux-end")?)?),
			TransportEnvelope::from(MuxCreditPackage::new(1, 128)),
			TransportEnvelope::from(MuxCancelPackage::new(5, CancelReason::Cancelled)),
			TransportEnvelope::from(GoAwayPackage::new(3, GoAwayReason::Shutdown)),
			TransportEnvelope::from(MuxPingPackage::new(false, 7)),
		])
	}
}
