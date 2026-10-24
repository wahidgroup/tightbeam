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

use crate::asn1::admission::DerAdmission;
use crate::der::{
	Decode, DecodeValue, Encode, EncodeValue, Header, Length, Reader, Result as DerResult, Sequence, SliceReader, Tag,
	Writer,
};
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::frame::Signed;

/// A `SEQUENCE` value together with the DER bytes that carry it.
///
/// Encoding a `WireDer` writes the stored bytes, so the bytes a sender hashed
/// are the bytes the receiver reads. Every handshake container and the frame
/// envelope is a `SEQUENCE`, so the type carries that tag.
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
	T: for<'a> Decode<'a>,
{
	type Error = crate::der::Error;

	/// Admit `der` under the CMS rules of the admission walk, then decode it
	/// once and keep it as received.
	fn try_from(der: &[u8]) -> DerResult<Self> {
		DerAdmission::Cms.admit(der)?;
		let value = T::from_der(der)?;
		let contents_at = contents_offset(der)?;
		Ok(Self { der: der.to_vec(), contents_at, value })
	}
}

impl<'a, T> Sequence<'a> for WireDer<T> where T: for<'b> Sequence<'b> {}

impl<'a, T> DecodeValue<'a> for WireDer<T>
where
	T: for<'b> Sequence<'b>,
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
		Ok(Self { der, contents_at, value })
	}
}

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
	use super::*;
	use crate::asn1::admission::fixtures::descending_attribute;
	use crate::der::asn1::{Any, ObjectIdentifier, OctetString};
	use crate::der::ErrorKind;
	use crate::x509::attr::Attribute;

	const OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.3.4");

	#[test]
	fn a_decoded_value_keeps_the_bytes_it_arrived_as() -> DerResult<()> {
		let values = [Any::encode_from(&OctetString::new(*b"a")?)?].try_into()?;
		let value = Attribute { oid: OID, values };
		let sent = WireDer::new(value)?;
		let bytes = sent.to_der()?;

		let received = WireDer::<Attribute>::from_der(&bytes)?;
		assert_eq!(received.der(), sent.der());
		assert_eq!(received.value(), sent.value());
		Ok(())
	}

	/// A SET OF out of DER order is refused before the decoder sorts it
	/// into another encoding than the received bytes (X.690 § 11.6).
	#[test]
	fn a_misordered_value_is_refused() {
		let misordered = [
			0x30, 0x0d, 0x06, 0x03, 0x2a, 0x03, 0x04, 0x31, 0x06, 0x04, 0x01, b'b', 0x04, 0x01, b'a',
		];

		let refused = WireDer::<Attribute>::try_from(&misordered[..]);
		assert_eq!(refused.map_err(|error| error.kind()), Err(ErrorKind::SetOrdering));
	}

	#[test]
	fn a_descending_set_is_refused_as_bytes() {
		let refused = WireDer::<Attribute>::try_from(descending_attribute().as_slice());
		assert_eq!(refused.map_err(|error| error.kind()), Err(ErrorKind::SetOrdering));
	}

	/// The decode under an enclosing tag admits the contents as the decode of
	/// the bytes alone does.
	#[test]
	fn a_descending_set_is_refused_as_a_value() {
		let refused = WireDer::<Attribute>::from_der(&descending_attribute());
		assert_eq!(refused.map_err(|error| error.kind()), Err(ErrorKind::SetOrdering));
	}
}
