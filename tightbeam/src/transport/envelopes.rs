//! Wire protocol data structures for transport layer envelopes

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(all(not(feature = "std"), feature = "x509"))]
use alloc::boxed::Box;
#[cfg(not(feature = "std"))]
use alloc::sync::Arc;
#[cfg(feature = "std")]
use std::sync::Arc;

use crate::asn1::Frame;
use crate::cms::enveloped_data::EncryptedContentInfo;
use crate::der::{Choice, Decode, Encode, EncodeValue, Length, Reader, Result as DerResult, Tag, Tagged, Writer};
use crate::policy::TransitStatus;

#[cfg(feature = "transport-multiplex")]
use crate::der::{Enumerated, Sequence};

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

/// Multiplexed request package carrying a stream identifier for correlation.
///
/// Stream correlation metadata travels inside the encrypted envelope payload,
/// so concurrency patterns never leak outside the AEAD.
#[cfg(feature = "transport-multiplex")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MuxedRequestPackage {
	pub(crate) stream_id: u32,
	pub(crate) message: Arc<Frame>,
}

#[cfg(feature = "transport-multiplex")]
impl MuxedRequestPackage {
	pub fn new(stream_id: u32, message: Frame) -> Self {
		Self { stream_id, message: Arc::new(message) }
	}

	pub fn stream_id(&self) -> u32 {
		self.stream_id
	}

	pub fn message(&self) -> &Arc<Frame> {
		&self.message
	}
}

#[cfg(feature = "transport-multiplex")]
impl EncodeValue for MuxedRequestPackage {
	fn value_len(&self) -> DerResult<Length> {
		let stream_len = self.stream_id.encoded_len()?;
		let message_len = self.message.as_ref().encoded_len()?;
		stream_len + message_len
	}

	fn encode_value(&self, writer: &mut impl Writer) -> DerResult<()> {
		self.stream_id.encode(writer)?;
		self.message.as_ref().encode(writer)
	}
}

#[cfg(feature = "transport-multiplex")]
impl Tagged for MuxedRequestPackage {
	fn tag(&self) -> Tag {
		Tag::Sequence
	}
}

#[cfg(feature = "transport-multiplex")]
impl<'a> Decode<'a> for MuxedRequestPackage {
	fn decode<R: Reader<'a>>(reader: &mut R) -> DerResult<Self> {
		reader.sequence(|reader| {
			let stream_id = u32::decode(reader)?;
			let frame = Frame::decode(reader)?;
			Ok(Self { stream_id, message: Arc::new(frame) })
		})
	}
}

/// Multiplexed response package pairing a stream identifier with the
/// existing [`ResponsePackage`] shape.
#[cfg(feature = "transport-multiplex")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MuxedResponsePackage {
	pub(crate) stream_id: u32,
	pub(crate) response: ResponsePackage,
}

#[cfg(feature = "transport-multiplex")]
impl MuxedResponsePackage {
	pub fn new(stream_id: u32, response: ResponsePackage) -> Self {
		Self { stream_id, response }
	}

	pub fn stream_id(&self) -> u32 {
		self.stream_id
	}

	pub fn response(&self) -> &ResponsePackage {
		&self.response
	}

	pub fn into_response(self) -> ResponsePackage {
		self.response
	}
}

#[cfg(feature = "transport-multiplex")]
impl EncodeValue for MuxedResponsePackage {
	fn value_len(&self) -> DerResult<Length> {
		let stream_len = self.stream_id.encoded_len()?;
		let response_len = self.response.encoded_len()?;
		stream_len + response_len
	}

	fn encode_value(&self, writer: &mut impl Writer) -> DerResult<()> {
		self.stream_id.encode(writer)?;
		self.response.encode(writer)
	}
}

#[cfg(feature = "transport-multiplex")]
impl Tagged for MuxedResponsePackage {
	fn tag(&self) -> Tag {
		Tag::Sequence
	}
}

#[cfg(feature = "transport-multiplex")]
impl<'a> Decode<'a> for MuxedResponsePackage {
	fn decode<R: Reader<'a>>(reader: &mut R) -> DerResult<Self> {
		reader.sequence(|reader| {
			let stream_id = u32::decode(reader)?;
			let response = ResponsePackage::decode(reader)?;
			Ok(Self { stream_id, response })
		})
	}
}

/// Reason a single stream was cancelled (RFC 9113 § 6.4 analog).
#[cfg(feature = "transport-multiplex")]
#[derive(Enumerated, Default, Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CancelReason {
	/// Requester is no longer interested in the response
	#[default]
	Cancelled = 0,
	/// Per-stream deadline elapsed before a response arrived
	Timeout = 1,
	/// Responder refused to process the stream
	Rejected = 2,
}

/// Cancel a single in-flight stream without tearing down the connection.
#[cfg(feature = "transport-multiplex")]
#[derive(Sequence, Debug, Clone, Copy, PartialEq, Eq)]
pub struct MuxCancelPackage {
	pub(crate) stream_id: u32,
	pub(crate) reason: CancelReason,
}

#[cfg(feature = "transport-multiplex")]
impl MuxCancelPackage {
	pub fn new(stream_id: u32, reason: CancelReason) -> Self {
		Self { stream_id, reason }
	}

	pub fn stream_id(&self) -> u32 {
		self.stream_id
	}

	pub fn reason(&self) -> CancelReason {
		self.reason
	}
}

/// Reason the connection is shutting down (RFC 9113 § 6.8 analog).
#[cfg(feature = "transport-multiplex")]
#[derive(Enumerated, Default, Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum GoAwayReason {
	/// Orderly shutdown initiated by the sender
	#[default]
	Shutdown = 0,
	/// Peer violated the multiplexing protocol
	ProtocolError = 1,
	/// Peer exceeded the cancel budget (RFC 9113 § 7
	/// ENHANCE_YOUR_CALM analog, CVE-2023-44487 hardening)
	EnhanceYourCalm = 2,
}

/// Graceful connection shutdown: streams at or below `last_stream_id`
/// drain to completion, newer ones are rejected.
#[cfg(feature = "transport-multiplex")]
#[derive(Sequence, Debug, Clone, Copy, PartialEq, Eq)]
pub struct GoAwayPackage {
	pub(crate) last_stream_id: u32,
	pub(crate) reason: GoAwayReason,
}

#[cfg(feature = "transport-multiplex")]
impl GoAwayPackage {
	pub fn new(last_stream_id: u32, reason: GoAwayReason) -> Self {
		Self { last_stream_id, reason }
	}

	pub fn last_stream_id(&self) -> u32 {
		self.last_stream_id
	}

	pub fn reason(&self) -> GoAwayReason {
		self.reason
	}
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
	MuxedRequest(MuxedRequestPackage),
	#[cfg(feature = "transport-multiplex")]
	#[asn1(context_specific = "5", constructed = "true")]
	MuxedResponse(MuxedResponsePackage),
	#[cfg(feature = "transport-multiplex")]
	#[asn1(context_specific = "6", constructed = "true")]
	MuxCancel(MuxCancelPackage),
	#[cfg(feature = "transport-multiplex")]
	#[asn1(context_specific = "7", constructed = "true")]
	GoAway(GoAwayPackage),
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
impl From<MuxedRequestPackage> for TransportEnvelope {
	fn from(pkg: MuxedRequestPackage) -> Self {
		Self::MuxedRequest(pkg)
	}
}

#[cfg(feature = "transport-multiplex")]
impl From<MuxedResponsePackage> for TransportEnvelope {
	fn from(pkg: MuxedResponsePackage) -> Self {
		Self::MuxedResponse(pkg)
	}
}

#[cfg(feature = "transport-multiplex")]
impl From<MuxCancelPackage> for TransportEnvelope {
	fn from(pkg: MuxCancelPackage) -> Self {
		Self::MuxCancel(pkg)
	}
}

#[cfg(feature = "transport-multiplex")]
impl From<GoAwayPackage> for TransportEnvelope {
	fn from(pkg: GoAwayPackage) -> Self {
		Self::GoAway(pkg)
	}
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
				expected_status: TransitStatus::Accepted,
				should_have_message: true,
			},
			PackageTestCase {
				// cspell:disable-next-line
				message_value: "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.",
				expected_status: TransitStatus::Accepted,
				should_have_message: true,
			},
			PackageTestCase {
				message_value: "",
				expected_status: TransitStatus::Accepted,
				should_have_message: true,
			},
			PackageTestCase {
				message_value: "Busy",
				expected_status: TransitStatus::Busy,
				should_have_message: false,
			},
			PackageTestCase {
				message_value: "Unauthorized",
				expected_status: TransitStatus::Unauthorized,
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
			status: TransitStatus::Accepted,
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
		let original = ResponsePackage { status: TransitStatus::Busy, message: None };

		let encoded = original.to_der()?;
		let decoded = ResponsePackage::from_der(&encoded)?;
		assert_eq!(original.status, decoded.status);
		assert_eq!(original.message, decoded.message);
		Ok(())
	}

	#[cfg(feature = "transport-multiplex")]
	fn as_muxed_test_cases() -> Vec<(u32, PackageTestCase)> {
		as_test_cases()
			.into_iter()
			.enumerate()
			.map(|(index, case)| (index as u32 * 2 + 1, case))
			.collect()
	}

	#[cfg(feature = "transport-multiplex")]
	#[test]
	fn test_muxed_request_package_encode_decode() -> Result<(), Box<dyn Error>> {
		for (stream_id, test_case) in as_muxed_test_cases() {
			let original =
				MuxedRequestPackage::new(stream_id, create_v0_tightbeam(Some(test_case.message_value), None));
			let encoded = original.to_der()?;
			let decoded = MuxedRequestPackage::from_der(&encoded)?;
			assert_eq!(original, decoded);
		}

		Ok(())
	}

	#[cfg(feature = "transport-multiplex")]
	#[test]
	fn test_muxed_response_package_encode_decode() -> Result<(), Box<dyn Error>> {
		for (stream_id, test_case) in as_muxed_test_cases() {
			let original = MuxedResponsePackage::new(stream_id, test_case.create_response());
			let encoded = original.to_der()?;
			let decoded = MuxedResponsePackage::from_der(&encoded)?;
			assert_eq!(original, decoded);
		}

		Ok(())
	}

	#[cfg(feature = "transport-multiplex")]
	#[test]
	fn test_mux_cancel_package_encode_decode() -> Result<(), Box<dyn Error>> {
		let cases = [
			MuxCancelPackage::new(1, CancelReason::Cancelled),
			MuxCancelPackage::new(3, CancelReason::Timeout),
			MuxCancelPackage::new(u32::MAX, CancelReason::Rejected),
		];
		for original in cases {
			let encoded = original.to_der()?;
			let decoded = MuxCancelPackage::from_der(&encoded)?;
			assert_eq!(original, decoded);
		}

		Ok(())
	}

	#[cfg(feature = "transport-multiplex")]
	#[test]
	fn test_go_away_package_encode_decode() -> Result<(), Box<dyn Error>> {
		let cases = [
			GoAwayPackage::new(0, GoAwayReason::Shutdown),
			GoAwayPackage::new(7, GoAwayReason::ProtocolError),
			GoAwayPackage::new(9, GoAwayReason::EnhanceYourCalm),
			GoAwayPackage::new(u32::MAX, GoAwayReason::Shutdown),
		];
		for original in cases {
			let encoded = original.to_der()?;
			let decoded = GoAwayPackage::from_der(&encoded)?;
			assert_eq!(original, decoded);
		}

		Ok(())
	}

	#[cfg(feature = "transport-multiplex")]
	#[test]
	fn test_muxed_envelope_variants_round_trip() -> Result<(), Box<dyn Error>> {
		let envelopes = vec![
			TransportEnvelope::from(MuxedRequestPackage::new(1, create_v0_tightbeam(Some("mux"), None))),
			TransportEnvelope::from(MuxedResponsePackage::new(
				1,
				ResponsePackage::new(TransitStatus::Accepted, Some(create_v0_tightbeam(Some("mux"), None))),
			)),
			TransportEnvelope::from(MuxCancelPackage::new(5, CancelReason::Cancelled)),
			TransportEnvelope::from(GoAwayPackage::new(3, GoAwayReason::Shutdown)),
		];
		for original in envelopes {
			let encoded = original.to_der()?;
			let decoded = TransportEnvelope::from_der(&encoded)?;
			assert_eq!(original, decoded);
		}

		Ok(())
	}
}
