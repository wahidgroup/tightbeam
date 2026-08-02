//! DER Sequence codecs that encode owned byte fields as OCTET STRING.
//!
//! `der_derive` 0.7 encodes an owned `Vec<u8>` field as `SEQUENCE OF INTEGER`.
//! That form costs three to four wire bytes per payload byte.
//! It contradicts the OCTET STRING schema this crate documents.
//! The derive accepts `#[asn1(type = "OCTET STRING")]` only for borrowed `&[u8]`.
//! This module keeps public fields as `Vec<u8>` while encoding the octet form.
//!
//! # Sources
//!
//! ITU publishes these Recommendations as PDF. Each link opens the 02/2021
//! English PDF at the file page that begins the cited clause (`#page=N`).
//!
//! - ITU-T X.680 (02/2021) § 23, notation for the octetstring type:
//!   <https://www.itu.int/rec/dologin_pub.asp?id=T-REC-X.680-202102-I%21%21PDF-E&lang=e&type=items#page=56>
//! - ITU-T X.680 (02/2021) § 25, notation for sequence types
//!   (`OPTIONAL` / `DEFAULT`):
//!   <https://www.itu.int/rec/dologin_pub.asp?id=T-REC-X.680-202102-I%21%21PDF-E&lang=e&type=items#page=57>
//! - ITU-T X.680 (02/2021) § 31, notation for prefixed types
//!   (`TaggedType` / `EXPLICIT`):
//!   <https://www.itu.int/rec/dologin_pub.asp?id=T-REC-X.680-202102-I%21%21PDF-E&lang=e&type=items#page=66>
//! - ITU-T X.690 (02/2021) § 8.7 / § 8.9, octetstring and sequence encodings:
//!   <https://www.itu.int/rec/dologin_pub.asp?id=T-REC-X.690-202102-I%21%21PDF-E&lang=e&type=items#page=18>
//! - ITU-T X.690 (02/2021) § 8.10 / § 8.14, sequence-of and prefixed-type
//!   encodings:
//!   <https://www.itu.int/rec/dologin_pub.asp?id=T-REC-X.690-202102-I%21%21PDF-E&lang=e&type=items#page=19>
//! - ITU-T X.690 (02/2021) § 11.5, set and sequence components with default
//!   value (DER omits a component equal to its default):
//!   <https://www.itu.int/rec/dologin_pub.asp?id=T-REC-X.690-202102-I%21%21PDF-E&lang=e&type=items#page=29>

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use crate::der::asn1::{OctetString, OctetStringRef};
use crate::der::{Decode, Reader, Result};

#[cfg(feature = "colony")]
use crate::der::{ErrorKind, FixedTag};

/// Decode one field through its own [`Decode`] impl, so macro expansions
/// do not depend on the `Reader` trait being in scope at the call site.
pub(crate) fn decode_plain<'a, R: Reader<'a>, T: Decode<'a>>(reader: &mut R) -> Result<T> {
	reader.decode()
}

/// Decode a trailing `DEFAULT` field: an absent field takes the schema
/// default (a field equal to its default is omitted from the encoding).
///
/// A present field equal to the default is refused as non-canonical.
/// Accepting both forms would give one value two distinct signed encodings.
///
/// Gated on `colony` with its only consumers, the colony message codecs,
/// so minimal builds carry no dead helper.
///
/// # Sources
///
/// - ITU-T X.690 (02/2021) § 11.5, set and sequence components with default
///   value:
///   <https://www.itu.int/rec/dologin_pub.asp?id=T-REC-X.690-202102-I%21%21PDF-E&lang=e&type=items#page=29>
#[cfg(feature = "colony")]
pub(crate) fn decode_or_default<'a, R: Reader<'a>, T>(reader: &mut R, default: T) -> Result<T>
where
	T: Decode<'a> + FixedTag + PartialEq,
{
	if reader.is_finished() {
		return Ok(default);
	}

	let value = reader.decode::<T>()?;
	if value == default {
		return Err(ErrorKind::Noncanonical { tag: T::TAG }.into());
	}

	Ok(value)
}

/// Encode a `DEFAULT` field: a value equal to its schema default
/// encodes nothing.
///
/// Gated on `colony` with its only consumers, the colony message codecs,
/// so minimal builds carry no dead helper.
///
/// # Sources
///
/// - ITU-T X.690 (02/2021) § 11.5, set and sequence components with default
///   value:
///   <https://www.itu.int/rec/dologin_pub.asp?id=T-REC-X.690-202102-I%21%21PDF-E&lang=e&type=items#page=29>
#[cfg(feature = "colony")]
pub(crate) fn default_field<T: Copy + PartialEq>(value: &T, default: T) -> Option<T> {
	if *value == default {
		return None;
	}

	Some(*value)
}

/// Decode one `OCTET STRING` into owned bytes.
pub(crate) fn decode_octets<'a, R: Reader<'a>>(reader: &mut R) -> Result<Vec<u8>> {
	Ok(OctetString::decode(reader)?.into_bytes())
}

/// Decode an optional `OCTET STRING` into owned bytes.
///
/// Gated on `colony` with its only consumers, the colony message codecs,
/// so minimal builds carry no dead helper.
#[cfg(feature = "colony")]
pub(crate) fn decode_octets_opt<'a, R: Reader<'a>>(reader: &mut R) -> Result<Option<Vec<u8>>> {
	Ok(Option::<OctetString>::decode(reader)?.map(OctetString::into_bytes))
}

/// Decode a `SEQUENCE OF OCTET STRING` into owned byte vectors.
///
/// Gated on `colony` with its only consumers, the colony message codecs,
/// so minimal builds carry no dead helper.
#[cfg(feature = "colony")]
pub(crate) fn decode_octets_seq<'a, R: Reader<'a>>(reader: &mut R) -> Result<Vec<Vec<u8>>> {
	Ok(Vec::<OctetString>::decode(reader)?
		.into_iter()
		.map(OctetString::into_bytes)
		.collect())
}

/// Borrow bytes as an encodable `OCTET STRING`.
pub(crate) fn octets_ref(bytes: &[u8]) -> Result<OctetStringRef<'_>> {
	OctetStringRef::new(bytes)
}

/// Borrow optional bytes as an encodable `OCTET STRING OPTIONAL`.
///
/// Gated on `colony` with its only consumers, the colony message codecs,
/// so minimal builds carry no dead helper.
#[cfg(feature = "colony")]
pub(crate) fn octets_opt_ref(bytes: &Option<Vec<u8>>) -> Result<Option<OctetStringRef<'_>>> {
	bytes.as_deref().map(OctetStringRef::new).transpose()
}

/// Borrow byte vectors as an encodable `SEQUENCE OF OCTET STRING`.
///
/// Gated on `colony` with its only consumers, the colony message codecs,
/// so minimal builds carry no dead helper.
#[cfg(feature = "colony")]
pub(crate) fn octets_seq_refs(list: &[Vec<u8>]) -> Result<Vec<OctetStringRef<'_>>> {
	list.iter().map(|bytes| OctetStringRef::new(bytes)).collect()
}

/// Implements [`der::Sequence`] with `OCTET STRING` wire encoding for byte
/// fields while the public field types remain `Vec<u8>` and `Vec<Vec<u8>>`.
///
/// The generated impls match `#[derive(der::Sequence)]` field for field.
/// Only the byte-field codec differs. Field kinds:
///
/// - `plain`: delegate to the field type's `Decode`/`Encode` impls
///   (including plain `Option<T>` fields).
/// - `octets`: `Vec<u8>` as `OCTET STRING`.
/// - `octets_opt`: `Option<Vec<u8>>` as `OCTET STRING OPTIONAL`.
/// - `octets_seq`: `Vec<Vec<u8>>` as `SEQUENCE OF OCTET STRING`.
/// - `ctx($tag)`: `Option<T>` as EXPLICIT `[$tag] T OPTIONAL`.
/// - `default($value)`: trailing `T DEFAULT $value` for `Copy` scalars.
///   The field is omitted when equal to `$value`.
///
/// # Sources
///
/// - ITU-T X.680 (02/2021) § 23 / § 25 / § 31:
///   <https://www.itu.int/rec/dologin_pub.asp?id=T-REC-X.680-202102-I%21%21PDF-E&lang=e&type=items#page=56>,
///   <https://www.itu.int/rec/dologin_pub.asp?id=T-REC-X.680-202102-I%21%21PDF-E&lang=e&type=items#page=57>,
///   <https://www.itu.int/rec/dologin_pub.asp?id=T-REC-X.680-202102-I%21%21PDF-E&lang=e&type=items#page=66>
/// - ITU-T X.690 (02/2021) § 8.7 / § 8.9:
///   <https://www.itu.int/rec/dologin_pub.asp?id=T-REC-X.690-202102-I%21%21PDF-E&lang=e&type=items#page=18>
/// - ITU-T X.690 (02/2021) § 8.10 / § 8.14:
///   <https://www.itu.int/rec/dologin_pub.asp?id=T-REC-X.690-202102-I%21%21PDF-E&lang=e&type=items#page=19>
/// - ITU-T X.690 (02/2021) § 11.5:
///   <https://www.itu.int/rec/dologin_pub.asp?id=T-REC-X.690-202102-I%21%21PDF-E&lang=e&type=items#page=29>
macro_rules! wire_sequence {
	(@decode $reader:ident, plain) => {
		$crate::wire::decode_plain($reader)?
	};
	(@decode $reader:ident, octets) => {
		$crate::wire::decode_octets($reader)?
	};
	(@decode $reader:ident, octets_opt) => {
		$crate::wire::decode_octets_opt($reader)?
	};
	(@decode $reader:ident, octets_seq) => {
		$crate::wire::decode_octets_seq($reader)?
	};
	(@decode $reader:ident, ctx($tag:expr)) => {
		::der::asn1::ContextSpecific::decode_explicit($reader, $tag)?.map(|field| field.value)
	};
	(@decode $reader:ident, default($value:expr)) => {
		$crate::wire::decode_or_default($reader, $value)?
	};
	(@encodable $self:ident, $field:ident, plain) => {
		&$self.$field
	};
	(@encodable $self:ident, $field:ident, octets) => {
		&$crate::wire::octets_ref(&$self.$field)?
	};
	(@encodable $self:ident, $field:ident, octets_opt) => {
		&$crate::wire::octets_opt_ref(&$self.$field)?
	};
	(@encodable $self:ident, $field:ident, octets_seq) => {
		&$crate::wire::octets_seq_refs(&$self.$field)?
	};
	(@encodable $self:ident, $field:ident, ctx($tag:expr)) => {
		&$self.$field.as_ref().map(|value| ::der::asn1::ContextSpecificRef {
			tag_number: $tag,
			tag_mode: ::der::TagMode::Explicit,
			value,
		})
	};
	(@encodable $self:ident, $field:ident, default($value:expr)) => {
		&$crate::wire::default_field(&$self.$field, $value)
	};
	($name:ident { $($field:ident : $kind:tt $(($tag:expr))?),+ $(,)? }) => {
		impl<'wire> ::der::DecodeValue<'wire> for $name {
			fn decode_value<R: ::der::Reader<'wire>>(
				reader: &mut R,
				header: ::der::Header,
			) -> ::der::Result<Self> {
				reader.read_nested(header.length, |reader| {
					$(let $field = wire_sequence!(@decode reader, $kind $(($tag))?);)+

					::core::result::Result::Ok(Self { $($field),+ })
				})
			}
		}

		impl ::der::EncodeValue for $name {
			fn value_len(&self) -> ::der::Result<::der::Length> {
				use ::der::Encode as _;

				let mut length = ::der::Length::ZERO;
				$(length = (length + wire_sequence!(@encodable self, $field, $kind $(($tag))?).encoded_len()?)?;)+

				::core::result::Result::Ok(length)
			}

			fn encode_value(&self, writer: &mut impl ::der::Writer) -> ::der::Result<()> {
				use ::der::Encode as _;

				$(wire_sequence!(@encodable self, $field, $kind $(($tag))?).encode(writer)?;)+

				::core::result::Result::Ok(())
			}
		}

		impl<'wire> ::der::Sequence<'wire> for $name {}
	};
}

pub(crate) use wire_sequence;

// The probe exercises every field kind, including the `colony`-gated
// optional and sequence helpers, so the tests share that gate.
#[cfg(all(test, feature = "colony"))]
mod tests {
	use super::*;
	use crate::der::{Encode, TagNumber};
	use crate::DigestInfo;

	#[derive(Debug, Clone, PartialEq, Eq)]
	struct Probe {
		count: u64,
		body: Vec<u8>,
		note: Option<Vec<u8>>,
		digests: Vec<Vec<u8>>,
		tagged: Option<DigestInfo>,
	}

	wire_sequence!(Probe {
		count: plain,
		body: octets,
		note: octets_opt,
		digests: octets_seq,
		tagged: ctx(TagNumber::N0),
	});

	fn probe() -> Probe {
		Probe {
			count: 7,
			body: vec![0x78; 4],
			note: Some(vec![0xAA, 0xBB]),
			digests: vec![vec![1, 2], vec![3]],
			tagged: None,
		}
	}

	#[test]
	fn round_trips_all_field_kinds() -> Result<()> {
		let original = probe();
		let encoded = original.to_der()?;
		let decoded = Probe::from_der(&encoded)?;

		assert_eq!(original, decoded);
		Ok(())
	}

	#[test]
	fn round_trips_absent_optionals() -> Result<()> {
		let original = Probe { note: None, digests: Vec::new(), ..probe() };
		let encoded = original.to_der()?;
		let decoded = Probe::from_der(&encoded)?;

		assert_eq!(original, decoded);
		Ok(())
	}

	#[test]
	fn encodes_bytes_as_octet_string() -> Result<()> {
		let encoded = probe().to_der()?;

		// The body must cost one wire byte per payload byte plus the two-byte
		// OCTET STRING header, never the SEQUENCE OF INTEGER form.
		let body = [0x04, 0x04, 0x78, 0x78, 0x78, 0x78];
		assert!(encoded.windows(body.len()).any(|window| window == body));
		Ok(())
	}

	#[derive(Debug, Clone, PartialEq, Eq)]
	struct BudgetProbe {
		budget: u8,
	}

	const BUDGET_DEFAULT: u8 = 7;

	wire_sequence!(BudgetProbe { budget: default(BUDGET_DEFAULT) });

	#[test]
	fn default_field_is_omitted_on_the_wire() -> Result<()> {
		let encoded = BudgetProbe { budget: BUDGET_DEFAULT }.to_der()?;
		let decoded = BudgetProbe::from_der(&encoded)?;

		assert_eq!(encoded, [0x30, 0x00]);
		assert_eq!(decoded.budget, BUDGET_DEFAULT);
		Ok(())
	}

	#[test]
	fn non_default_field_round_trips() -> Result<()> {
		let decoded = BudgetProbe::from_der(&BudgetProbe { budget: 5 }.to_der()?)?;

		assert_eq!(decoded.budget, 5);
		Ok(())
	}

	#[test]
	fn present_default_value_is_refused_as_noncanonical() {
		// SEQUENCE { INTEGER 7 }: an encoder violating ITU-T X.690 § 11.5 by
		// writing the schema default instead of omitting the field.
		// See the module-level `# Sources` for the recommendation link.
		let encoded = [0x30, 0x03, 0x02, 0x01, 0x07];

		assert!(BudgetProbe::from_der(&encoded).is_err());
	}
}
