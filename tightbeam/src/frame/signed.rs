//! The signed CMS structures the crate holds at its wire slots, and the
//! reader of the certificates a `SignedData` carries as they arrived.

#[cfg(all(not(feature = "std"), any(feature = "transport-cms", feature = "transport-hpke")))]
use alloc::vec::Vec;

use core::ops::Deref;

use crate::asn1::admission::{Canonical, DerAdmission};
use crate::cms::signed_data::{SignedData, SignerInfo};
use crate::der::{
	DecodeValue, EncodeValue, Header, Length, Reader, Result as DerResult, Sequence, SliceReader, Tag, TagNumber,
	Writer,
};

#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::der::{AnyRef, Decode, Tagged};

/// The `[0]` tag of the `certificates` field of a `SignedData`.
pub(crate) const CERTIFICATES_TAG: Tag = Tag::ContextSpecific { constructed: true, number: TagNumber::N0 };

/// The `[1]` tag of the `crls` field of a `SignedData`.
const CRLS_TAG: Tag = Tag::ContextSpecific { constructed: true, number: TagNumber::N1 };

/// A CMS `SignerInfo` or `SignedData` (RFC 5652 §5) at a wire slot of the
/// crate.
///
/// The signer of `crypto::sign` builds every value the crate emits, and the
/// DER decoder yields every value it reads. The value reads as `T`, encodes
/// as `T` with every SET in DER order, and is immutable.
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

	/// Read the contents of the element `header` heads from `reader`, admit
	/// them under the CMS rules of the admission walk, decode them as `T`, and
	/// hold the value to them.
	///
	/// # Errors
	///
	/// - The errors of the admission walk.
	/// - The decode error of `T`, or [`crate::der::ErrorKind::TrailingData`] -- they are no single `T`.
	/// - [`crate::der::ErrorKind::Noncanonical`] -- they are not the DER of the value.
	fn decode_arrived<'a, R: Reader<'a>>(reader: &mut R, header: Header) -> DerResult<Self>
	where
		T: DecodeValue<'a> + Canonical,
	{
		let contents = reader.read_slice(header.length)?;
		DerAdmission::Cms.admit(contents)?;

		let mut contents_reader = SliceReader::new(contents)?;
		let value = T::decode_value(&mut contents_reader, header)?;
		let value = contents_reader.finish(value)?;
		DerAdmission::arrived_as(&value, contents)?;
		Ok(Self(value))
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

/// `der` 0.7 orders each universal SET of a `SignerInfo` by its octets, as
/// DER does: the RDNs of an `IssuerAndSerialNumber`, the attributes, and
/// their values. Its order reads the header of an element before the
/// contents, so the value of an RDN with the shorter encoding sorts first, as
/// X.690 § 11.6 sorts it.
impl Canonical for SignerInfo {}

/// The contents go out with every SET in DER order (X.690 § 11.6). `der` 0.7
/// sorts a SET OF a CHOICE in another order: the `SignerInfos` of a
/// countersigned `SignedData`, and the `certificates` and `crls` that its
/// schema tags IMPLICIT. The contents therefore pass through one buffer that
/// `DerAdmission` arranges.
impl Canonical for SignedData {
	fn encode_canonical(&self, writer: &mut impl Writer) -> DerResult<()> {
		DerAdmission::write_arranged(self, &[CERTIFICATES_TAG, CRLS_TAG], writer)
	}
}

/// The value encodes in its canonical form, the form a decode holds an
/// arrival to.
impl EncodeValue for Signed<SignerInfo> {
	fn value_len(&self) -> DerResult<Length> {
		self.0.value_len()
	}

	fn encode_value(&self, writer: &mut impl Writer) -> DerResult<()> {
		self.0.encode_canonical(writer)
	}
}

/// The value encodes in its canonical form, the form a decode holds an
/// arrival to.
impl EncodeValue for Signed<SignedData> {
	fn value_len(&self) -> DerResult<Length> {
		self.0.value_len()
	}

	fn encode_value(&self, writer: &mut impl Writer) -> DerResult<()> {
		self.0.encode_canonical(writer)
	}
}

/// The contents pass the CMS rules of the admission walk before the
/// `SignerInfo` decodes them, and the decode holds the value to them, so
/// they are its DER.
impl<'a> DecodeValue<'a> for Signed<SignerInfo> {
	fn decode_value<R: Reader<'a>>(reader: &mut R, header: Header) -> DerResult<Self> {
		Self::decode_arrived(reader, header)
	}
}

/// The contents pass the CMS rules of the admission walk before the
/// `SignedData` decodes them, and the decode holds the value to them, so they
/// are its DER and each certificate of its set is the DER it arrived as.
impl<'a> DecodeValue<'a> for Signed<SignedData> {
	fn decode_value<R: Reader<'a>>(reader: &mut R, header: Header) -> DerResult<Self> {
		Self::decode_arrived(reader, header)
	}
}

/// A `SignerInfo` is a SEQUENCE, so the wrapper is one, with that tag.
impl<'a> Sequence<'a> for Signed<SignerInfo> {}

/// A `SignedData` is a SEQUENCE, so the wrapper is one, with that tag.
impl<'a> Sequence<'a> for Signed<SignedData> {}

/// The `certificates` field of a `SignedData` as it arrived, and the bytes
/// each of its choices arrived as.
///
/// It is the one reader of a presented set as it arrived: its field, which a
/// handshake transcript binds, and its count, which a reader bounds before a
/// typed decode sorts the set.
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
pub(crate) struct ArrivedCertificates<'a> {
	/// The field, from its `[0]` tag on.
	field: &'a [u8],
	/// The bytes of each choice of the set, in the order they arrived.
	choices: Vec<&'a [u8]>,
}

#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
impl<'a> ArrivedCertificates<'a> {
	/// The `certificates` field of `der`, the encoding of a `SignedData` from
	/// its tag on, or `None` when `der` carries no such field.
	///
	/// # Errors
	///
	/// - [`crate::der::ErrorKind::TagUnexpected`] -- `der` carries a second `certificates` field.
	/// - The header error -- `der`, its fields, or the field is no run of DER elements.
	pub(crate) fn read(der: &'a (impl AsRef<[u8]> + ?Sized)) -> DerResult<Option<Self>> {
		let mut reader = SliceReader::new(der.as_ref())?;
		let header = Header::decode(&mut reader)?;
		let fields = reader.read_slice(header.length)?;

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

		Ok(Some(Self { field, choices }))
	}

	/// The field as it arrived, from its `[0]` tag on, which a handshake
	/// transcript binds.
	pub(crate) fn field(&self) -> &'a [u8] {
		self.field
	}

	/// The number of choices the set arrived with.
	pub(crate) fn count(&self) -> usize {
		self.choices.len()
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::asn1::admission::fixtures::{descending_attribute, tlv};
	use crate::der::asn1::ObjectIdentifier;
	use crate::der::oid::db::rfc4519::{CN, OU};
	use crate::der::{Decode, Encode, ErrorKind};
	use crate::oids::{HASH_SHA3_256, SIGNER_ECDSA_WITH_SHA256};

	/// The wrapper admits its contents before the typed decode, so the walk
	/// refuses an `Attribute` of descending values before the `SignerInfo`
	/// decode reads it.
	#[test]
	fn a_descending_set_is_refused() {
		let refused = Signed::<SignerInfo>::from_der(&descending_attribute());
		assert_eq!(refused.map_err(|error| error.kind()), Err(ErrorKind::SetOrdering));
	}

	/// The DER of an `AttributeTypeAndValue` of `oid` whose value is the
	/// UTF8String `value`.
	fn type_and_value(oid: ObjectIdentifier, value: &str) -> Vec<u8> {
		let oid = oid.to_der().expect("a test OID encodes");
		tlv(Tag::Sequence, &[oid, tlv(Tag::Utf8String, value.as_bytes())].concat())
	}

	/// The `OU` of a two-valued RDN. Its OID sorts after the OID of `CN`, and
	/// its encoding is the shorter of the two.
	fn unit() -> Vec<u8> {
		type_and_value(OU, "a")
	}

	/// The `CN` of a two-valued RDN, the longer of the two encodings.
	fn common_name() -> Vec<u8> {
		type_and_value(CN, "a longer common name")
	}

	/// The DER of a `SignerInfo` (RFC 5652 § 5.3) as a client of another
	/// implementation writes it: its `sid` names an issuer of one RDN that
	/// holds `values` in the order given.
	fn signer_info_issued_by(values: [Vec<u8>; 2]) -> Vec<u8> {
		let algorithm = |oid: ObjectIdentifier| tlv(Tag::Sequence, &oid.to_der().expect("a test OID encodes"));
		let one = tlv(Tag::Integer, &[0x01]);
		let issuer = tlv(Tag::Sequence, &tlv(Tag::Set, &values.concat()));
		let sid = tlv(Tag::Sequence, &[issuer, one.clone()].concat());
		let digest = algorithm(HASH_SHA3_256);
		let signature_algorithm = algorithm(SIGNER_ECDSA_WITH_SHA256);
		let signature = tlv(Tag::OctetString, &[0x00; 8]);

		tlv(Tag::Sequence, &[one, sid, digest, signature_algorithm, signature].concat())
	}

	/// X.690 § 11.6 orders the values of an RDN by their encodings, so the
	/// shorter `OU` goes first, though the OID of `CN` sorts first. `der`
	/// writes that order back, so the hold admits it.
	#[test]
	fn a_signer_whose_issuer_holds_a_two_valued_rdn_in_der_order_is_admitted() -> DerResult<()> {
		let arrived = signer_info_issued_by([unit(), common_name()]);
		let admitted = Signed::<SignerInfo>::from_der(&arrived)?;
		assert_eq!(admitted.to_der()?, arrived);
		Ok(())
	}

	/// The same RDN in the order of its OIDs is not its DER.
	#[test]
	fn a_two_valued_rdn_in_the_order_of_its_oids_is_refused() {
		let arrived = signer_info_issued_by([common_name(), unit()]);
		let refused = Signed::<SignerInfo>::from_der(&arrived);
		assert_eq!(refused.map_err(|error| error.kind()), Err(ErrorKind::SetOrdering));
	}
}
