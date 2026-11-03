//! The wire messages of the colony work plane.
//!
//! A client submits work with these messages alone, so they compile on every
//! target with `std`, `wasm32-unknown-unknown` included. The `colony-wire`
//! feature exposes this module, and the rest of the colony stays under
//! `colony`.

use crate::asn1::Frame;
use crate::constants::DEFAULT_HOP_BUDGET;
use crate::der::asn1::ContextSpecificRef;
use crate::der::{Encode, EncodeValue, FixedTag, Length, Tag, TagMode, TagNumber, Writer};
use crate::policy::TransitStatus;
use crate::urn::Urn;
use crate::utils::{decode, encode};
use crate::wire::{octets_ref, wire_sequence};
use crate::{Beamable, TightBeamError};

/// The context tag of the `Work` alternative of `ClusterRequest`.
const WORK_ALTERNATIVE: TagNumber = TagNumber::N2;

/// The work request envelope for cluster routing.
///
/// Clients send it to the cluster gateway, which selects a local servlet or a
/// peer gateway by `servlet_type` and delivers the client frame in `payload`
/// to the servlet byte-for-byte.
#[derive(Debug, Beamable, Clone, PartialEq)]
pub struct ClusterWorkRequest {
	/// The target servlet type URN, such as `urn:tightbeam::servlet:ping`.
	pub servlet_type: Urn<'static>,
	/// The DER bytes of the client's complete end-to-end [`Frame`].
	///
	/// The frame's `message` is the servlet's typed input. Gateways forward
	/// these bytes unmodified, so the client's signature, integrity, and
	/// previous-frame linkage stay verifiable at the servlet
	/// (`Frame::verify`, under `signature`).
	pub payload: Vec<u8>,
	/// The relay budget: the count of gateway forwards that remain for this
	/// work.
	///
	/// - A client origin stamps the [`DEFAULT_HOP_BUDGET`] sentinel through
	///   [`ClusterWorkRequest::new`], so gateway policy decides the budget.
	/// - Each gateway clamps the inbound value to its own `max_hops`, so one
	///   clamp rule covers the origin sentinel and a relayed value.
	/// - A gateway that selects a peer route re-emits with the clamped budget
	///   decremented ([`ClusterWorkRequest::into_relayed`]).
	pub hops_remaining: u8,
}

wire_sequence!(ClusterWorkRequest {
	servlet_type: plain,
	payload: octets,
	hops_remaining: default(DEFAULT_HOP_BUDGET),
});

impl ClusterWorkRequest {
	/// Builds origin work from a client, with the client's complete frame
	/// nested as the end-to-end payload. The sentinel budget defers the hop
	/// cap to the first gateway's `max_hops` policy.
	///
	/// # Errors
	///
	/// - [`TightBeamError::SerializationError`] -- `frame` does not encode.
	pub fn new(servlet_type: Urn<'static>, frame: &Frame) -> Result<Self, TightBeamError> {
		Ok(Self { servlet_type, payload: encode(frame)?, hops_remaining: DEFAULT_HOP_BUDGET })
	}

	/// Re-emits the work toward a peer with the relay budget that remains. A
	/// `0` budget is the terminal hop, so the receiver serves locally only.
	#[must_use]
	pub fn into_relayed(mut self, hops_remaining: u8) -> Self {
		self.hops_remaining = hops_remaining;
		self
	}

	/// Wraps `work` in the hop-local transport frame the gateway expects. The
	/// frame encodes once, into the message of the wrapper.
	///
	/// # Errors
	///
	/// - [`TightBeamError::SerializationError`] -- `work` or the envelope does not encode.
	///
	/// # Examples
	///
	/// ```
	/// # #[cfg(feature = "builder")]
	/// # {
	/// use tightbeam::builder::TypeBuilder;
	/// use tightbeam::colony::work::ClusterWorkRequest;
	/// use tightbeam::{Opaque, Version};
	///
	/// let composed = Version::V1.compose::<Opaque>().with_id(b"work").with_order(1);
	/// let work = composed.with_message(Opaque::new(*b"input")?).build()?;
	/// let carrier = ClusterWorkRequest::transport_frame("urn:tightbeam::servlet:ping".parse()?, &work)?;
	///
	/// // The client emits `carrier` on its own transport, and unwraps the
	/// // gateway's reply with `ClusterWorkResponse::served_reply`.
	/// assert_eq!(carrier.metadata().id(), work.metadata().id());
	/// # }
	/// # Ok::<(), tightbeam::TightBeamError>(())
	/// ```
	pub fn transport_frame(servlet_type: Urn<'static>, work: &Frame) -> Result<Frame, TightBeamError> {
		let lent = LentWork { servlet_type: &servlet_type, payload: FrameOctets(work) };
		lent.wrapped(work.metadata().id())
	}

	/// Wraps `der`, the DER of the client's complete frame, in the hop-local
	/// transport frame the gateway expects, as [`Self::transport_frame`] does.
	///
	/// A client that holds its frame as DER sends these exact bytes. The
	/// wrapper reads the id in place from the head of the frame, and the bytes
	/// copy once, into the message of the wrapper. The servlet parses the
	/// whole frame.
	///
	/// # Errors
	///
	/// - [`TightBeamError::SerializationError`] -- `der` opens with no frame
	///   head, or the envelope does not encode.
	pub fn transport_frame_from_der(
		servlet_type: Urn<'static>,
		der: &(impl AsRef<[u8]> + ?Sized),
	) -> Result<Frame, TightBeamError> {
		let der = der.as_ref();
		let lent = LentWork { servlet_type: &servlet_type, payload: octets_ref(der)? };
		lent.wrapped(Frame::id_in(der)?)
	}
}

/// Origin work as `ClusterRequest::Work` carries it, with the payload lent in
/// place of the bytes that [`ClusterWorkRequest::payload`] owns.
///
/// It encodes the layout that `wire_sequence!` gives [`ClusterWorkRequest`],
/// with the origin budget, which the wire omits as the `DEFAULT`. The macro
/// encodes the owned type alone, and
/// `a_transport_frame_carries_the_work_alternative` pins the two encodings.
struct LentWork<'a, P> {
	servlet_type: &'a Urn<'static>,
	payload: P,
}

impl<P: Encode> LentWork<'_, P> {
	/// This work in the hop-local transport frame, under the id of the work
	/// frame it nests.
	///
	/// The wrapper serves routing alone. Its message is the encoded
	/// `ClusterRequest::Work` alternative, so the client's own frame travels
	/// inside unmodified.
	///
	/// # Errors
	///
	/// - [`TightBeamError::SerializationError`] -- the envelope does not encode.
	fn wrapped(&self, correlation_id: impl AsRef<[u8]>) -> Result<Frame, TightBeamError> {
		let tag_mode = TagMode::Explicit;
		let alternative = ContextSpecificRef { tag_number: WORK_ALTERNATIVE, tag_mode, value: self };
		let message = encode(&alternative)?;

		Ok(Frame::v0(correlation_id, message))
	}
}

impl<P: Encode> EncodeValue for LentWork<'_, P> {
	fn value_len(&self) -> crate::der::Result<Length> {
		self.servlet_type.encoded_len()? + self.payload.encoded_len()?
	}

	fn encode_value(&self, writer: &mut impl Writer) -> crate::der::Result<()> {
		self.servlet_type.encode(writer)?;
		self.payload.encode(writer)
	}
}

impl<P> FixedTag for LentWork<'_, P> {
	const TAG: Tag = Tag::Sequence;
}

/// A frame as the content of an `OCTET STRING`, which encodes the frame into
/// its writer with no buffer between the two.
struct FrameOctets<'a>(&'a Frame);

impl EncodeValue for FrameOctets<'_> {
	fn value_len(&self) -> crate::der::Result<Length> {
		self.0.encoded_len()
	}

	fn encode_value(&self, writer: &mut impl Writer) -> crate::der::Result<()> {
		self.0.encode(writer)
	}
}

impl FixedTag for FrameOctets<'_> {
	const TAG: Tag = Tag::OctetString;
}

/// The work response from the cluster.
#[derive(Debug, Beamable, Clone, PartialEq)]
pub struct ClusterWorkResponse {
	/// The status of the routing and the execution.
	pub status: TransitStatus,
	/// The DER bytes of the servlet's complete response [`Frame`] on
	/// success, and [`None`] on a refusal.
	///
	/// Gateways return the servlet's reply frame unmodified, so its signature
	/// and metadata stay verifiable at the client (`Frame::verify`, under
	/// `signature`).
	///
	/// - [`ClusterWorkResponse::into_frame`] decodes the payload.
	/// - [`ClusterWorkResponse::served`] resolves success and refusal in one step.
	pub payload: Option<Vec<u8>>,
}

wire_sequence!(ClusterWorkResponse { status: plain, payload: octets_opt });

impl ClusterWorkResponse {
	/// Creates a successful response that carries the servlet's encoded
	/// response frame.
	#[inline]
	pub fn ok(payload: impl Into<Vec<u8>>) -> Self {
		Self { status: TransitStatus::Ok, payload: Some(payload.into()) }
	}

	/// Creates an error response with `status`.
	#[inline]
	pub fn err(status: TransitStatus) -> Self {
		Self { status, payload: None }
	}

	/// Decodes the servlet's complete response frame from the payload.
	///
	/// A refusal carries no payload and yields [`None`]. A caller that treats
	/// a refusal as an error uses [`ClusterWorkResponse::served`] instead.
	///
	/// # Errors
	///
	/// - [`TightBeamError::SerializationError`] -- the payload does not decode as a frame.
	pub fn into_frame(self) -> Result<Option<Frame>, TightBeamError> {
		match self.payload {
			Some(payload) => Ok(Some(decode(&payload)?)),
			None => Ok(None),
		}
	}

	/// Resolves the response into the servlet's frame or a typed error.
	///
	/// The unary work plane is request-reply, so a served request always
	/// carries the servlet's complete response frame.
	///
	/// # Errors
	///
	/// - [`TightBeamError::WorkRefused`] -- the status is not `Ok`, so the work was refused.
	/// - [`TightBeamError::MissingResponse`] -- the status is `Ok` with no
	///   payload, which violates the plane contract.
	/// - [`TightBeamError::SerializationError`] -- the payload does not decode as a frame.
	pub fn served(self) -> Result<Frame, TightBeamError> {
		decode(&self.served_payload()?)
	}

	/// Resolves the response into the servlet's frame and the DER it arrived
	/// as, or a typed error. A client that relays the frame keeps its exact
	/// bytes this way.
	///
	/// # Errors
	///
	/// - The errors of [`Self::served`].
	pub fn into_served_der(self) -> Result<(Frame, Vec<u8>), TightBeamError> {
		let payload = self.served_payload()?;
		let frame = decode(&payload)?;

		Ok((frame, payload))
	}

	/// The payload of a served request, or the refusal in its place.
	fn served_payload(self) -> Result<Vec<u8>, TightBeamError> {
		if self.status != TransitStatus::Ok {
			return Err(TightBeamError::WorkRefused(self.status));
		}

		self.payload.ok_or(TightBeamError::MissingResponse)
	}

	/// Unwraps a gateway reply down to the servlet's response frame.
	///
	/// It is the inverse of [`ClusterWorkRequest::transport_frame`]: the reply
	/// is the hop-local wrapper, with the servlet's own frame inside it.
	///
	/// # Errors
	///
	/// - [`TightBeamError::MissingResponse`] -- the gateway answered with no frame.
	/// - The errors of [`Frame::decode_message`] -- the reply is no carrier of a work response.
	/// - Any error that [`Self::served`] reports for the decoded response.
	pub fn served_reply(reply: Option<Frame>) -> Result<Frame, TightBeamError> {
		let reply = reply.ok_or(TightBeamError::MissingResponse)?;
		let response: Self = reply.decode_message()?;

		response.served()
	}
}

#[cfg(all(test, feature = "colony"))]
mod tests {
	use super::*;
	use crate::colony::protocol::ClusterRequest;
	use crate::testing::{TestFrame, TestResult};

	/// The servlet type of the wire tests.
	fn ping() -> Result<Urn<'static>, TightBeamError> {
		Ok("urn:tightbeam::servlet:ping".parse()?)
	}

	/// The `der` `Choice` derive takes the tag of `Work` as a literal, and
	/// [`ClusterRequest`] needs the runtime `colony-wire` omits, so
	/// `WORK_ALTERNATIVE` restates that literal. This test pins the two.
	#[test]
	fn a_transport_frame_carries_the_work_alternative() -> TestResult {
		let work = TestFrame::v1(None, Some("work"));
		let request = ClusterWorkRequest::new(ping()?, &work)?;
		let alternative = encode(&ClusterRequest::Work(request))?;

		let carrier = ClusterWorkRequest::transport_frame(ping()?, &work)?;
		assert_eq!(carrier.message(), alternative);
		assert_eq!(carrier.metadata().id(), work.metadata().id());
		Ok(())
	}

	#[test]
	fn work_wrapped_from_der_matches_work_wrapped_from_its_frame() -> TestResult {
		let work = TestFrame::v1(None, Some("work"));
		let from_der = ClusterWorkRequest::transport_frame_from_der(ping()?, &encode(&work)?)?;
		assert_eq!(from_der, ClusterWorkRequest::transport_frame(ping()?, &work)?);
		Ok(())
	}

	#[test]
	fn the_id_of_der_work_is_read_in_place() -> TestResult {
		let work = TestFrame::v1(None, Some("work"));
		let der = encode(&work)?;

		let id = Frame::id_in(&der)?;
		assert_eq!(id, work.metadata().id());
		assert!(der.as_ptr_range().contains(&id.as_ptr()));
		Ok(())
	}

	// The id read refuses a head that is no frame head: an id past the end of
	// its frame or of its metadata, a frame or metadata that is a `SET`, and a
	// version this crate does not know. Each case keeps every length valid, so
	// the one check it names refuses it.
	crate::tb_cases! {
		fn a_head_that_is_no_frame_head_yields_no_id(head: [u8; 10]) {
			assert!(matches!(Frame::id_in(&head), Err(TightBeamError::SerializationError(_))));
		}
		cases {
			id_past_the_frame => [0x30, 0x00, 0x0A, 0x01, 0x00, 0x30, 0x03, 0x04, 0x01, 0x41],
			id_past_the_metadata => [0x30, 0x08, 0x0A, 0x01, 0x00, 0x30, 0x00, 0x04, 0x01, 0x41],
			frame_that_is_a_set => [0x31, 0x08, 0x0A, 0x01, 0x00, 0x30, 0x03, 0x04, 0x01, 0x41],
			unknown_version => [0x30, 0x08, 0x0A, 0x01, 0x09, 0x30, 0x03, 0x04, 0x01, 0x41],
			metadata_that_is_a_set => [0x30, 0x08, 0x0A, 0x01, 0x00, 0x31, 0x03, 0x04, 0x01, 0x41],
		}
	}

	#[test]
	fn work_from_der_refuses_bytes_that_are_no_frame() -> TestResult {
		let garbled = ClusterWorkRequest::transport_frame_from_der(ping()?, &[0xDE, 0xAD]);
		assert!(matches!(garbled, Err(TightBeamError::SerializationError(_))));
		Ok(())
	}

	#[test]
	fn served_der_keeps_the_exact_bytes_beside_their_frame() -> TestResult {
		let reply = TestFrame::v1(None, Some("reply"));
		let response = ClusterWorkResponse::ok(encode(&reply)?);

		let (frame, der) = response.into_served_der()?;
		assert_eq!(der, encode(&reply)?);
		assert_eq!(frame, reply);
		Ok(())
	}

	#[test]
	fn served_der_refuses_bytes_that_are_no_frame() {
		let garbled = ClusterWorkResponse::ok([0xDE, 0xAD]).into_served_der();
		assert!(matches!(garbled, Err(TightBeamError::SerializationError(_))));
	}

	#[test]
	fn served_der_refuses_a_refusal() {
		let refused = ClusterWorkResponse::err(TransitStatus::NotFound).into_served_der();
		assert!(matches!(refused, Err(TightBeamError::WorkRefused(TransitStatus::NotFound))));
	}

	#[test]
	fn served_der_refuses_a_bodiless_ok() {
		let bodiless = ClusterWorkResponse { status: TransitStatus::Ok, payload: None }.into_served_der();
		assert!(matches!(bodiless, Err(TightBeamError::MissingResponse)));
	}
}
