//! The signed CMS structures the crate holds at its wire slots, and the
//! reader of the certificates a `SignedData` carries as they arrived.

#[cfg(not(feature = "std"))]
use alloc::{vec, vec::Vec};

use core::ops::Deref;

use crate::asn1::admission::DerAdmission;
use crate::cms::cert::x509::Certificate;
use crate::cms::cert::CertificateChoices;
use crate::cms::signed_data::{CertificateSet, SignedData, SignerInfo};
use crate::der::{
	AnyRef, Decode, DecodeValue, Encode, EncodeValue, Header, Length, Reader, Result as DerResult, Sequence,
	SliceReader, SliceWriter, Tag, TagNumber, Tagged, Writer,
};

/// The `[0]` tag of the `certificates` field of a `SignedData`.
pub(crate) const CERTIFICATES_TAG: Tag = Tag::ContextSpecific { constructed: true, number: TagNumber::N0 };

/// The `[1]` tag of the `crls` field of a `SignedData`.
const CRLS_TAG: Tag = Tag::ContextSpecific { constructed: true, number: TagNumber::N1 };

/// A CMS `SignerInfo` or `SignedData` (RFC 5652 §5) at a wire slot of the
/// crate.
///
/// The signer of `crypto::sign` builds every value the crate emits, and the
/// DER decoder yields every value it reads. The value reads as `T`, it
/// encodes as `T` with every SET in DER order, and it is immutable.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signed<T>(T);

impl<T> Signed<T> {
	/// Wrap a structure the signer built. The seal is the signer's alone.
	#[cfg(feature = "signature")]
	pub(crate) fn new(inner: T, _seal: crate::crypto::sign::SignerSeal) -> Self {
		Self(inner)
	}

	/// Take the structure out of the wrapper.
	pub fn into_inner(self) -> T {
		self.0
	}

	/// Decode `contents`, the contents octets of the element `header` heads,
	/// as `T`, and refuse octets past the value.
	///
	/// # Errors
	///
	/// - The decode error of `T`, or [`crate::der::ErrorKind::TrailingData`] -- `contents` is no single `T`.
	fn decode_contents<'a>(contents: &'a [u8], header: Header) -> DerResult<Self>
	where
		T: DecodeValue<'a>,
	{
		let mut contents_reader = SliceReader::new(contents)?;
		let value = T::decode_value(&mut contents_reader, header)?;
		contents_reader.finish(Self(value))
	}
}

impl<T> Deref for Signed<T> {
	type Target = T;

	fn deref(&self) -> &T {
		&self.0
	}
}

impl<T> AsRef<T> for Signed<T> {
	fn as_ref(&self) -> &T {
		&self.0
	}
}

/// The value encodes in place. `der` 0.7 orders each universal SET of a
/// `SignerInfo` by its octets, as DER does: the RDNs of an
/// `IssuerAndSerialNumber`, the attributes, and their values.
impl EncodeValue for Signed<SignerInfo> {
	fn value_len(&self) -> DerResult<Length> {
		self.0.value_len()
	}

	fn encode_value(&self, writer: &mut impl Writer) -> DerResult<()> {
		self.0.encode_value(writer)
	}
}

/// The contents go out with every SET in DER order (X.690 § 11.6). `der` 0.7
/// sorts a SET OF a CHOICE in another order: the `SignerInfos` of a
/// countersigned `SignedData`, and the `certificates` and `crls` that its
/// schema tags IMPLICIT. The contents therefore pass through one buffer that
/// `DerAdmission` arranges.
impl EncodeValue for Signed<SignedData> {
	fn value_len(&self) -> DerResult<Length> {
		self.0.value_len()
	}

	fn encode_value(&self, writer: &mut impl Writer) -> DerResult<()> {
		let contents_len = usize::try_from(self.0.value_len()?)?;
		let mut contents = vec![0u8; contents_len];

		let mut contents_writer = SliceWriter::new(&mut contents);
		self.0.encode_value(&mut contents_writer)?;
		let written = contents_writer.finish()?.len();
		contents.truncate(written);

		DerAdmission::arrange(&mut contents)?;
		DerAdmission::arrange_fields(&mut contents, &[CERTIFICATES_TAG, CRLS_TAG])?;
		writer.write(&contents)
	}
}

/// The contents pass the CMS rules of the admission walk before the
/// `SignerInfo` decodes them.
impl<'a> DecodeValue<'a> for Signed<SignerInfo> {
	fn decode_value<R: Reader<'a>>(reader: &mut R, header: Header) -> DerResult<Self> {
		let contents = reader.read_slice(header.length)?;
		DerAdmission::Cms.admit(contents)?;
		Self::decode_contents(contents, header)
	}
}

/// The contents pass the CMS rules of the admission walk before the
/// `SignedData` decodes them, and each certificate of the decoded set is then
/// the DER one choice of the set arrived as.
impl<'a> DecodeValue<'a> for Signed<SignedData> {
	fn decode_value<R: Reader<'a>>(reader: &mut R, header: Header) -> DerResult<Self> {
		// 1. Walk the contents, and read the `certificates` field as it arrived.
		let contents = reader.read_slice(header.length)?;
		DerAdmission::Cms.admit(contents)?;
		let arrived = ArrivedCertificates::of_fields(contents)?;

		// 2. Decode the contents, and hold each certificate to the bytes it arrived as.
		let signed = Self::decode_contents(contents, header)?;
		let certificates = signed.0.certificates.as_ref();
		arrived.map(|arrived| arrived.admit(certificates)).transpose()?;
		Ok(signed)
	}
}

/// A `SignerInfo` is a SEQUENCE, so the wrapper is one, with that tag.
impl<'a> Sequence<'a> for Signed<SignerInfo> {}

/// A `SignedData` is a SEQUENCE, so the wrapper is one, with that tag.
impl<'a> Sequence<'a> for Signed<SignedData> {}

/// The `certificates` field of a `SignedData` as it arrived, and the bytes
/// each of its choices arrived as.
///
/// It is the one reader of a presented set. The decode of a
/// [`Signed<SignedData>`], and the client's read of a reply, hold each
/// certificate of the typed set to it.
pub(crate) struct ArrivedCertificates<'a> {
	/// The field, from its `[0]` tag on.
	#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
	field: &'a [u8],
	/// The bytes of each choice of the set, in the order they arrived.
	choices: Vec<&'a [u8]>,
}

impl<'a> ArrivedCertificates<'a> {
	/// The `certificates` field of `der`, the encoding of a `SignedData` from
	/// its tag on, or `None` when `der` carries no such field.
	///
	/// # Errors
	///
	/// - The errors of [`Self::of_fields`], or the header error -- `der` starts with no DER header.
	#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
	pub(crate) fn read(der: &'a (impl AsRef<[u8]> + ?Sized)) -> DerResult<Option<Self>> {
		let mut reader = SliceReader::new(der.as_ref())?;
		let header = Header::decode(&mut reader)?;
		let fields = reader.read_slice(header.length)?;
		Self::of_fields(fields)
	}

	/// The `certificates` field of `fields`, the contents of a `SignedData`,
	/// or `None` when they carry no such field.
	///
	/// # Errors
	///
	/// - [`crate::der::ErrorKind::TagUnexpected`] -- `fields` carries a second `certificates` field.
	/// - The header error -- `fields` or the field is no run of DER elements.
	fn of_fields(fields: &'a [u8]) -> DerResult<Option<Self>> {
		// 1. Find the `certificates` field as it arrived.
		let mut reader = SliceReader::new(fields)?;
		let mut field = None;
		while !reader.is_finished() {
			let arrived = reader.tlv_bytes()?;
			if AnyRef::from_der(arrived)?.tag() == CERTIFICATES_TAG {
				// The typed decode keeps the first `[0]`, so a second one
				// names a set that decode skipped (CWE-436).
				if field.is_some() {
					return Err(CERTIFICATES_TAG.unexpected_error(None));
				}

				field = Some(arrived);
			}
		}
		let Some(field) = field else {
			return Ok(None);
		};

		// 2. Take the bytes of each choice of its set.
		let mut elements = SliceReader::new(AnyRef::from_der(field)?.value())?;
		let mut choices = Vec::new();
		while !elements.is_finished() {
			choices.push(elements.tlv_bytes()?);
		}

		Ok(Some(Self {
			#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
			field,
			choices,
		}))
	}

	/// The field as it arrived, from its `[0]` tag on, which a handshake
	/// transcript binds.
	#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
	pub(crate) fn field(&self) -> &'a [u8] {
		self.field
	}

	/// The number of choices the set arrived with.
	#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
	pub(crate) fn count(&self) -> usize {
		self.choices.len()
	}

	/// Hold each certificate of `typed`, the set decoded from the bytes this
	/// field was read from, to the bytes one choice arrived as.
	///
	/// - A store verifies a signature over the DER of the TBS
	///   (RFC 5280 § 4.1.1.3), so a certificate in another encoding would
	///   validate as the certificate its CA signed.
	/// - The typed decode of a SET refuses two equal elements, so each
	///   certificate of a set matches a choice of its own.
	///
	/// # Errors
	///
	/// - [`crate::der::ErrorKind::Noncanonical`] -- a certificate arrived in
	///   another encoding than its DER (X.690 § 11.5).
	/// - The encode error of a certificate.
	pub(crate) fn admit(&self, typed: Option<&CertificateSet>) -> DerResult<()> {
		let certificates = typed.into_iter().flat_map(|set| set.0.iter()).filter_map(Self::named);
		for certificate in certificates {
			if !self.arrived_as(certificate)? {
				return Err(Tag::Sequence.non_canonical_error());
			}
		}

		Ok(())
	}

	/// Whether one choice of the set arrived as the DER of `certificate`.
	///
	/// # Errors
	///
	/// - The encode error of `certificate`.
	fn arrived_as(&self, certificate: &Certificate) -> DerResult<bool> {
		let len = usize::try_from(certificate.encoded_len()?)?;
		for arrived in self.choices.iter().filter(|arrived| arrived.len() == len) {
			if Comparing::encodes_as(certificate, arrived)? {
				return Ok(true);
			}
		}

		Ok(false)
	}

	/// The certificate `choice` carries, or `None` for a choice of another
	/// format, which names no certificate (RFC 5652 § 10.2.2).
	pub(crate) fn named(choice: &CertificateChoices) -> Option<&Certificate> {
		match choice {
			CertificateChoices::Certificate(certificate) => Some(certificate),
			CertificateChoices::Other(_) => None,
		}
	}

	/// The certificate `choice` carries, moved out of it, as
	/// [`Self::named`] reads it.
	#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
	pub(crate) fn into_named(choice: CertificateChoices) -> Option<Certificate> {
		match choice {
			CertificateChoices::Certificate(certificate) => Some(certificate),
			CertificateChoices::Other(_) => None,
		}
	}
}

/// A [`Writer`] that compares the octets an encoder writes with the octets
/// it expects, run by run, and holds no copy of them.
struct Comparing<'a> {
	/// The expected octets the encoder has yet to write, or `None` once a run
	/// differs from them.
	rest: Option<&'a [u8]>,
}

impl<'a> Comparing<'a> {
	/// Whether `value` encodes as exactly `expected`.
	///
	/// # Errors
	///
	/// - The encode error of `value`.
	fn encodes_as(value: &impl Encode, expected: &'a [u8]) -> DerResult<bool> {
		let mut comparing = Self { rest: Some(expected) };
		value.encode(&mut comparing)?;
		Ok(comparing.rest.is_some_and(<[u8]>::is_empty))
	}
}

impl Writer for Comparing<'_> {
	fn write(&mut self, slice: &[u8]) -> DerResult<()> {
		self.rest = self.rest.and_then(|rest| rest.strip_prefix(slice));
		Ok(())
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::asn1::admission::fixtures::descending_attribute;
	use crate::der::asn1::OctetString;
	use crate::der::ErrorKind;

	/// The DER of an OCTET STRING of `octets`.
	fn octet_string(octets: &[u8]) -> Vec<u8> {
		let value = OctetString::new(octets).expect("a test OCTET STRING fits a DER length");
		value.to_der().expect("a test OCTET STRING encodes")
	}

	/// The wrapper admits its contents before the typed decode reads them, so
	/// an `Attribute` of descending values is refused at the walk, before the
	/// `SignerInfo` decode reads it.
	#[test]
	fn a_descending_set_is_refused() {
		let refused = Signed::<SignerInfo>::from_der(&descending_attribute());
		assert_eq!(refused.map_err(|error| error.kind()), Err(ErrorKind::SetOrdering));
	}

	#[test]
	fn an_encoding_equal_to_the_expected_octets_matches() -> DerResult<()> {
		let expected = octet_string(b"abc");
		let matches = Comparing::encodes_as(&OctetString::new(*b"abc")?, &expected)?;
		assert!(matches);
		Ok(())
	}

	#[test]
	fn an_encoding_that_differs_in_its_last_octet_is_refused() -> DerResult<()> {
		let expected = octet_string(b"abx");
		let matches = Comparing::encodes_as(&OctetString::new(*b"abc")?, &expected)?;
		assert!(!matches);
		Ok(())
	}

	#[test]
	fn an_encoding_that_ends_short_of_the_expected_octets_is_refused() -> DerResult<()> {
		let expected = [octet_string(b"abc"), vec![0x00]].concat();
		let matches = Comparing::encodes_as(&OctetString::new(*b"abc")?, &expected)?;
		assert!(!matches);
		Ok(())
	}

	#[test]
	fn an_encoding_that_runs_past_the_expected_octets_is_refused() -> DerResult<()> {
		let expected = octet_string(b"abc");
		let matches = Comparing::encodes_as(&OctetString::new(*b"abc")?, &expected[..expected.len() - 1])?;
		assert!(!matches);
		Ok(())
	}
}
