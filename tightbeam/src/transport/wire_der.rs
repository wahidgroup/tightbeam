//! A decoded value that keeps the exact bytes it crossed the wire as.
//!
//! A handshake transcript binds the messages both endpoints exchanged, so it
//! MUST hash the bytes that crossed the wire rather than a re-encoding of
//! what a decoder produced. [`WireDer`] is created once where a message is
//! decoded or built, and every later step reads the value and the bytes from
//! it, so no step parses or encodes the message a second time.

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use crate::der::{
	Decode, DecodeValue, Encode, EncodeValue, Header, Length, Reader, Result as DerResult, Sequence, SliceReader, Tag,
	Writer,
};

/// A `SEQUENCE` value together with the DER bytes that carry it.
///
/// Encoding a `WireDer` writes the stored bytes, so the bytes a sender hashed
/// are the bytes the receiver reads. Every handshake container is a
/// `SEQUENCE`, so the type carries that tag.
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

impl<T> WireDer<T> {
	/// Return the DER bytes that carry the value.
	pub fn der(&self) -> &[u8] {
		&self.der
	}

	/// Return the decoded value.
	pub fn value(&self) -> &T {
		&self.value
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

	/// Decode `der` once and keep it as received.
	fn try_from(der: &[u8]) -> DerResult<Self> {
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
		let contents = reader.read_vec(header.length)?;
		let own_header = Header::new(Tag::Sequence, header.length)?;
		let contents_at = usize::try_from(own_header.encoded_len()?)?;
		let mut der = Vec::with_capacity(contents_at.saturating_add(contents.len()));

		own_header.encode_to_vec(&mut der)?;
		der.extend_from_slice(&contents);

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
	use crate::der::asn1::{Any, ObjectIdentifier, OctetString};
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

	/// A decoder that normalises what it reads, as `der` sorts a SET OF,
	/// yields a value whose own encoding differs from the received bytes. The
	/// received bytes are what a transcript binds.
	#[test]
	fn a_normalised_value_keeps_the_bytes_it_arrived_as() -> DerResult<()> {
		let misordered = [
			0x30, 0x0d, 0x06, 0x03, 0x2a, 0x03, 0x04, 0x31, 0x06, 0x04, 0x01, b'b', 0x04, 0x01, b'a',
		];

		let received = WireDer::<Attribute>::try_from(&misordered[..])?;
		assert_eq!(received.der(), misordered);
		assert_ne!(received.value().to_der()?, misordered);
		assert_eq!(received.to_der()?, misordered);
		Ok(())
	}
}
