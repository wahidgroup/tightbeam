//! A decoded value that keeps the exact bytes it crossed the wire as.
//!
//! [`WireDer`] is created once where a message is decoded or built, and every
//! later step reads the value and the bytes from it, so the endpoint parses or
//! encodes each message once. Two readers need those bytes:
//!
//! - A handshake transcript MUST hash the bytes that crossed the wire, not a re-encoding of them.
//! - A frame's envelope opens against its authenticated attributes as they arrived (RFC 5083 §2.1).

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use crate::asn1::admission::{Canonical, Comparing, DerAdmission};
use crate::asn1::{AuthEnvelopedData, ContentInfo};
use crate::der::{
	Decode, DecodeValue, Encode, EncodeValue, Header, Length, Reader, Result as DerResult, Sequence, SliceReader, Tag,
	Writer,
};

#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::frame::Signed;
#[cfg(feature = "transport")]
use crate::transport::handshake::negotiation::{SecurityAccept, TransportAccept};

/// A `SEQUENCE` value together with the DER bytes that carry it.
///
/// Encoding a `WireDer` writes the stored bytes, so the bytes a sender hashed
/// are the bytes the receiver reads. Each decode holds the value to the bytes
/// it arrived as, so a received value names every element its bytes carry.
/// Every handshake container and the frame envelope is a `SEQUENCE`, so the
/// type carries that tag.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WireDer<T> {
	der: Vec<u8>,
	contents_at: usize,
	value: T,
}

impl<T: Encode> WireDer<T> {
	/// Wrap a value this endpoint built, carried by its own encoding.
	///
	/// # Errors
	///
	/// - The encoding error when `value` does not encode.
	pub fn new(value: T) -> DerResult<Self> {
		let der = value.to_der()?;
		let contents_at = contents_offset(&der)?;

		Ok(Self { der, contents_at, value })
	}
}

#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
impl<T> WireDer<T>
where
	Signed<T>: Encode,
{
	/// Wrap a structure the signer built, carried by the encoding its
	/// [`Signed`] wrapper writes, with every SET in DER order.
	///
	/// # Errors
	///
	/// - The encoding error when `signed` does not encode.
	pub(crate) fn signed(signed: Signed<T>) -> DerResult<Self> {
		let der = signed.to_der()?;
		let contents_at = contents_offset(&der)?;

		Ok(Self { der, contents_at, value: signed.into_inner() })
	}
}

impl<T> WireDer<T> {
	/// Return the DER bytes that carry the value.
	pub fn der(&self) -> &[u8] {
		&self.der
	}

	/// Return the decoded value.
	pub fn value(&self) -> &T {
		&self.value
	}

	/// Take the decoded value, and drop the bytes that carried it.
	pub fn into_value(self) -> T {
		self.value
	}

	/// Take the DER bytes and the decoded value apart, so a step that consumes
	/// the value still reads the bytes it arrived as.
	pub fn into_parts(self) -> (Vec<u8>, T) {
		(self.der, self.value)
	}

	/// Return the contents octets, after the tag and length.
	///
	/// Every constructor reads `contents_at` from the header of these same
	/// bytes, so the range is always inside them.
	fn contents(&self) -> &[u8] {
		self.der.get(self.contents_at..).unwrap_or_default()
	}
}

impl<T> TryFrom<&[u8]> for WireDer<T>
where
	T: for<'a> Decode<'a> + Canonical,
{
	type Error = crate::der::Error;

	/// Admit `der` under the CMS rules of the admission walk, decode it once,
	/// hold the value to the bytes it arrived as, and keep them.
	fn try_from(der: &[u8]) -> DerResult<Self> {
		let value: T = DerAdmission::Cms.decode(der)?;
		let contents_at = contents_offset(der)?;

		let received = Self { der: der.to_vec(), contents_at, value };
		DerAdmission::arrived_as(&received.value, received.contents())?;
		Ok(received)
	}
}

impl<'a, T> Sequence<'a> for WireDer<T> where T: for<'b> Sequence<'b> + Canonical {}

impl<'a, T> DecodeValue<'a> for WireDer<T>
where
	T: for<'b> Sequence<'b> + Canonical,
{
	/// Keep the contents octets as received under the `SEQUENCE` tag.
	///
	/// DER admits one length encoding per length, so the rebuilt header is the
	/// one the sender wrote when the enclosing field tags the value
	/// explicitly, as every handshake envelope does. An implicitly tagged
	/// field puts a context tag on the wire, which these bytes replace with
	/// the `SEQUENCE` tag.
	fn decode_value<R: Reader<'a>>(reader: &mut R, header: Header) -> DerResult<Self> {
		let contents = reader.read_slice(header.length)?;
		DerAdmission::Cms.admit(contents)?;

		let own_header = Header::new(Tag::Sequence, header.length)?;
		let contents_at = usize::try_from(own_header.encoded_len()?)?;
		let mut der = Vec::with_capacity(contents_at.saturating_add(contents.len()));

		own_header.encode_to_vec(&mut der)?;
		der.extend_from_slice(contents);

		let value = T::from_der(&der)?;
		DerAdmission::arrived_as(&value, contents)?;
		Ok(Self { der, contents_at, value })
	}
}

/// `der` 0.7 sorts the `recipientInfos` of an `AuthEnvelopedData`, a SET OF a
/// CHOICE, in another order than X.690 § 11.6, so the contents go out with
/// every universal SET in DER order. Its attributes are a SET OF a SEQUENCE,
/// which `der` orders as DER does.
impl Canonical for AuthEnvelopedData {
	fn encode_canonical(&self, writer: &mut impl Writer) -> DerResult<()> {
		DerAdmission::write_arranged(self, &[], writer)
	}

	/// Rule A admitted every universal SET of `arrived` in DER order, and the
	/// canonical encoding moves no other element, so `arrived` is that encoding
	/// when the `der` encoding streams equal to it.
	fn is_encoded_as(&self, arrived: &[u8]) -> DerResult<bool> {
		let is_der_order = Comparing::is_written_by(arrived, |writer| self.encode_value(writer))?;
		if is_der_order {
			return Ok(true);
		}

		Comparing::is_written_by(arrived, |writer| self.encode_canonical(writer))
	}
}

/// `der` 0.7 writes a `ContentInfo` in DER: its content type, and its content
/// as it arrived.
impl Canonical for ContentInfo {}

/// `der` 0.7 writes a `SecurityAccept`, the profile a server selected, in DER.
#[cfg(feature = "transport")]
impl Canonical for SecurityAccept {}

/// `der` 0.7 writes a `TransportAccept`, a SEQUENCE of a flag, integers, and
/// budgets, in DER.
#[cfg(feature = "transport")]
impl Canonical for TransportAccept {}

impl<T> EncodeValue for WireDer<T>
where
	T: for<'b> Sequence<'b>,
{
	fn value_len(&self) -> DerResult<Length> {
		Length::try_from(self.contents().len())
	}

	fn encode_value(&self, writer: &mut impl Writer) -> DerResult<()> {
		writer.write(self.contents())
	}
}

/// Where the contents octets start in a DER encoding.
fn contents_offset(der: &[u8]) -> DerResult<usize> {
	let mut reader = SliceReader::new(der)?;
	let header = Header::decode(&mut reader)?;

	let offset = usize::try_from(header.encoded_len()?)?;
	Ok(offset)
}

#[cfg(test)]
mod tests {
	use crate::asn1::admission::fixtures::{der_refusal, descending_attribute};
	use crate::der::asn1::{Any, ObjectIdentifier, OctetString};
	use crate::der::ErrorKind;
	use crate::testing::TestResult;
	use crate::x509::attr::Attribute;

	use super::*;

	const OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.3.4");

	/// A decode of the bytes a peer sent into a [`WireDer`] of `T`.
	type DecodePath<T> = fn(&[u8]) -> DerResult<WireDer<T>>;

	/// `der` 0.7 orders the values of an `Attribute` as DER does.
	impl Canonical for Attribute {}

	/// The decode of the sent bytes holds the sent value and keeps those bytes.
	#[test]
	fn a_decoded_value_keeps_the_bytes_it_arrived_as() -> TestResult {
		let values = [Any::encode_from(&OctetString::new(*b"a")?)?].try_into()?;
		let value = Attribute { oid: OID, values };
		let sent = WireDer::new(value)?;
		let bytes = sent.to_der()?;

		let received = WireDer::<Attribute>::from_der(&bytes)?;
		assert_eq!(received, sent);
		Ok(())
	}

	/// An `Attribute` whose two values arrive as `b` then `a`, out of DER
	/// order.
	const MISORDERED: [u8; 15] = [
		0x30, 0x0d, 0x06, 0x03, 0x2a, 0x03, 0x04, 0x31, 0x06, 0x04, 0x01, b'b', 0x04, 0x01, b'a',
	];

	// A SET OF out of DER order is refused before the decoder sorts it into
	// another encoding than the received bytes (X.690 § 11.6).
	crate::tb_cases! {
		fn a_set_out_of_der_order_is_refused((decode, der): (DecodePath<Attribute>, Vec<u8>)) {
			assert_eq!(der_refusal(decode(&der)), Some(ErrorKind::SetOrdering));
		}
		cases {
			misordered_as_bytes => (|der| WireDer::try_from(der), MISORDERED.to_vec()),
			descending_as_bytes => (|der| WireDer::try_from(der), descending_attribute()),
			/// The decode under an enclosing tag admits the contents as the
			/// decode of the bytes alone does.
			descending_as_a_value => (|der| WireDer::from_der(der), descending_attribute()),
		}
	}

	/// The fields of `AuthEnvelopedData` (RFC 5083 § 2.1), with its
	/// context-specific tags, over placeholder values.
	#[derive(Clone, Debug, PartialEq, Eq, Sequence)]
	struct EnvelopeLayout {
		version: u8,
		#[asn1(
			context_specific = "0",
			tag_mode = "IMPLICIT",
			constructed = "true",
			optional = "true"
		)]
		originator_info: Option<Any>,
		recipient_infos: Any,
		content_info: OctetString,
		#[asn1(
			context_specific = "1",
			tag_mode = "IMPLICIT",
			constructed = "true",
			optional = "true"
		)]
		auth_attrs: Option<Any>,
		mac: OctetString,
		#[asn1(
			context_specific = "2",
			tag_mode = "IMPLICIT",
			constructed = "true",
			optional = "true"
		)]
		unauth_attrs: Option<Any>,
	}

	/// `der` 0.7 writes the layout in DER.
	impl Canonical for EnvelopeLayout {}

	/// `SEQUENCE { 0, SET {}, "", [1] {}, "" }`, the DER of an
	/// [`EnvelopeLayout`].
	const CANONICAL_LAYOUT: [u8; 13] = [0x30, 0x0b, 0x02, 0x01, 0x00, 0x31, 0x00, 0x04, 0x00, 0xa1, 0x00, 0x04, 0x00];

	/// [`CANONICAL_LAYOUT`] with a stray `[0] { NULL }` before `[1]`, where
	/// X.690 § 8.9.2 admits no element.
	const STRAY_BEFORE_ATTRIBUTES: [u8; 17] = [
		0x30, 0x0f, 0x02, 0x01, 0x00, 0x31, 0x00, 0x04, 0x00, 0xa0, 0x02, 0x05, 0x00, 0xa1, 0x00, 0x04, 0x00,
	];

	/// [`CANONICAL_LAYOUT`] with a stray `[1] { NULL }` after `mac`, where
	/// only `[2]` may follow.
	const STRAY_AFTER_MAC: [u8; 17] = [
		0x30, 0x0f, 0x02, 0x01, 0x00, 0x31, 0x00, 0x04, 0x00, 0xa1, 0x00, 0x04, 0x00, 0xa1, 0x02, 0x05, 0x00,
	];

	/// The refusal of a value that arrived in another encoding than its DER.
	const NONCANONICAL: ErrorKind = ErrorKind::Noncanonical { tag: Tag::Sequence };

	/// A value whose bytes are its DER is admitted and keeps those bytes.
	#[test]
	fn a_value_in_its_der_is_admitted() -> TestResult {
		let admitted = WireDer::<EnvelopeLayout>::try_from(&CANONICAL_LAYOUT[..])?;
		assert_eq!(admitted.der(), CANONICAL_LAYOUT);
		Ok(())
	}

	// The hold of a decoded value to its arrival refuses a stray context tag.
	crate::tb_cases! {
		fn a_stray_context_tag_is_refused((decode, der): (DecodePath<EnvelopeLayout>, &[u8])) {
			assert_eq!(der_refusal(decode(der)), Some(NONCANONICAL));
		}
		cases {
			/// `der` skips a context-specific element whose number is below
			/// the one it looks for, so the hold refuses the stray `[0]`.
			as_bytes => (|der| WireDer::try_from(der), &STRAY_BEFORE_ATTRIBUTES),
			/// The decode under an enclosing tag holds the value to its
			/// arrival as the decode of the bytes alone does.
			as_a_value => (|der| WireDer::from_der(der), &STRAY_AFTER_MAC),
		}
	}
}
