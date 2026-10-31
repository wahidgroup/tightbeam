//! DER Sequence codecs that encode owned byte fields as OCTET STRING.
//!
//! `der_derive` 0.7 encodes an owned `Vec<u8>` field as `SEQUENCE OF INTEGER`,
//! which costs three to four wire bytes per payload byte and contradicts the
//! OCTET STRING schema this crate documents. The derive accepts
//! `#[asn1(type = "OCTET STRING")]` only for a borrowed `&[u8]`, so this
//! module keeps public fields as `Vec<u8>` and encodes the octet form.
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

use crate::der::asn1::{ContextSpecific, OctetString, OctetStringRef};
use crate::der::{Decode, Reader, Result, Tag, TagNumber};

#[cfg(feature = "colony")]
use crate::der::{ErrorKind, FixedTag};

/// Decode one field through its own [`Decode`] impl, so a macro expansion
/// compiles whatever traits its call site imports.
pub(crate) fn decode_plain<'a, R: Reader<'a>, T: Decode<'a>>(reader: &mut R) -> Result<T> {
	reader.decode()
}

/// Decode an optional EXPLICIT `[number]` field, the `ctx` kind.
///
/// `der` 0.7 skips a context field numbered below `number` while it looks for
/// `number`, so a repeated field, or one out of schema order, would decode as
/// if it were absent. DER encodes each field of a SEQUENCE once, in the order
/// of the definition, so this decoder refuses a context field numbered below
/// `number` ahead of it.
///
/// # Sources
///
/// - ITU-T X.690 (02/2021) § 8.9.2, the order of sequence components:
///   <https://www.itu.int/rec/dologin_pub.asp?id=T-REC-X.690-202102-I%21%21PDF-E&lang=e&type=items#page=18>
pub(crate) fn decode_ctx_explicit<'a, R: Reader<'a>, T: Decode<'a>>(
	reader: &mut R,
	number: TagNumber,
) -> Result<Option<T>> {
	if let Some(octet) = reader.peek_byte() {
		let next = Tag::try_from(octet)?;
		if next.is_context_specific() && next.number() < number {
			let expected = Tag::ContextSpecific { constructed: true, number };
			return Err(next.unexpected_error(Some(expected)));
		}
	}

	let field = ContextSpecific::<T>::decode_explicit(reader, number)?;
	Ok(field.map(|field| field.value))
}

/// Decode a trailing `DEFAULT` field: an absent field takes the schema
/// default (a field equal to its default is omitted from the encoding).
///
/// A present field equal to the default is refused as non-canonical.
/// Accepting both forms would give one value two distinct signed encodings.
///
/// It sits behind the `colony` gate of its only consumers, the colony
/// message codecs, so a minimal build omits it.
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

/// Encode a `DEFAULT` field, which DER omits when its value equals the
/// schema default.
///
/// It sits behind the `colony` gate of its only consumers, the colony
/// message codecs, so a minimal build omits it.
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
/// It sits behind the `colony` gate of its only consumers, the colony
/// message codecs, so a minimal build omits it.
#[cfg(feature = "colony")]
pub(crate) fn decode_octets_opt<'a, R: Reader<'a>>(reader: &mut R) -> Result<Option<Vec<u8>>> {
	Ok(Option::<OctetString>::decode(reader)?.map(OctetString::into_bytes))
}

/// Decode a `SEQUENCE OF OCTET STRING` into owned byte vectors.
///
/// It sits behind the `colony` gate of its only consumers, the colony
/// message codecs, so a minimal build omits it.
#[cfg(feature = "colony")]
pub(crate) fn decode_octets_seq<'a, R: Reader<'a>>(reader: &mut R) -> Result<Vec<Vec<u8>>> {
	Ok(Vec::<OctetString>::decode(reader)?
		.into_iter()
		.map(OctetString::into_bytes)
		.collect())
}

/// Borrow bytes as an encodable `OCTET STRING`.
pub(crate) fn octets_ref(bytes: &(impl AsRef<[u8]> + ?Sized)) -> Result<OctetStringRef<'_>> {
	let bytes = bytes.as_ref();
	OctetStringRef::new(bytes)
}

/// Borrow optional bytes as an encodable `OCTET STRING OPTIONAL`.
///
/// It sits behind the `colony` gate of its only consumers, the colony
/// message codecs, so a minimal build omits it.
#[cfg(feature = "colony")]
pub(crate) fn octets_opt_ref(bytes: &Option<Vec<u8>>) -> Result<Option<OctetStringRef<'_>>> {
	bytes.as_deref().map(OctetStringRef::new).transpose()
}

/// Borrow byte vectors as an encodable `SEQUENCE OF OCTET STRING`.
///
/// It sits behind the `colony` gate of its only consumers, the colony
/// message codecs, so a minimal build omits it.
#[cfg(feature = "colony")]
pub(crate) fn octets_seq_refs(list: &(impl AsRef<[Vec<u8>]> + ?Sized)) -> Result<Vec<OctetStringRef<'_>>> {
	let list = list.as_ref();
	list.iter().map(|bytes| OctetStringRef::new(bytes)).collect()
}

/// Implements [`der::Sequence`] with `OCTET STRING` wire encoding for byte
/// fields while the public field types remain `Vec<u8>` and `Vec<Vec<u8>>`.
///
/// The generated impls match `#[derive(der::Sequence)]` field for field.
/// Only the byte-field codec differs. Field kinds:
///
/// - `plain`: delegate to the field type's `Decode`/`Encode` impls (including plain `Option<T>` fields).
/// - `octets`: `Vec<u8>` as `OCTET STRING`.
/// - `octets_opt`: `Option<Vec<u8>>` as `OCTET STRING OPTIONAL`.
/// - `octets_seq`: `Vec<Vec<u8>>` as `SEQUENCE OF OCTET STRING`.
/// - `ctx($tag)`: `Option<T>` as EXPLICIT `[$tag] T OPTIONAL`.
/// - `default($value)`: trailing `T DEFAULT $value` for `Copy` scalars.
///   The field is omitted when equal to `$value`.
///
/// A trailing `where $check` names a `fn(&Self) -> der::Result<()>`:
///
/// - The decoder runs it on the assembled value, in the same pass that reads the fields.
/// - It rejects a cross-field constraint, so no decoded value skips it.
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
		$crate::wire::decode_ctx_explicit($reader, $tag)?
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
	($name:ident { $($field:ident : $kind:tt $(($tag:expr))?),+ $(,)? } $(where $check:path)?) => {
		impl<'wire> ::der::DecodeValue<'wire> for $name {
			fn decode_value<R: ::der::Reader<'wire>>(
				reader: &mut R,
				header: ::der::Header,
			) -> ::der::Result<Self> {
				reader.read_nested(header.length, |reader| {
					$(let $field = wire_sequence!(@decode reader, $kind $(($tag))?);)+
					let value = Self { $($field),+ };
					$($check(&value)?;)?

					::core::result::Result::Ok(value)
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

#[cfg(test)]
mod tests {
	use crate::der::Encode;
	use crate::testing::fixtures::der_round_trip;
	use crate::testing::TestResult;

	#[cfg(feature = "colony")]
	use crate::asn1::admission::fixtures::der_refusal;
	#[cfg(feature = "colony")]
	use crate::der::TagNumber;
	#[cfg(feature = "colony")]
	use crate::DigestInfo;

	#[cfg(feature = "colony")]
	use super::*;

	#[derive(Debug, Clone, PartialEq, Eq)]
	struct Probe {
		count: u64,
		body: Vec<u8>,
	}

	wire_sequence!(Probe { count: plain, body: octets });

	fn probe() -> Probe {
		Probe { count: 7, body: Vec::from([0x78; 4]) }
	}

	/// A plain field and an octet field decode again to the value that wrote
	/// them.
	#[test]
	fn round_trips_plain_and_octet_fields() {
		assert_eq!(der_round_trip(&probe()), probe());
	}

	/// An owned byte field costs one wire byte per payload byte plus the
	/// two-byte OCTET STRING header, which is less than the SEQUENCE OF
	/// INTEGER form costs.
	#[test]
	fn encodes_bytes_as_octet_string() -> TestResult {
		let encoded = probe().to_der()?;
		// SEQUENCE { INTEGER 7, OCTET STRING 78 78 78 78 }.
		assert_eq!(encoded, [0x30, 0x09, 0x02, 0x01, 0x07, 0x04, 0x04, 0x78, 0x78, 0x78, 0x78]);
		Ok(())
	}

	// The optional, sequence-of, context-tagged, and default field kinds are
	// gated with the helpers they expand to, so their probes share that gate.
	#[cfg(feature = "colony")]
	#[derive(Debug, Clone, PartialEq, Eq)]
	struct ColonyProbe {
		count: u64,
		note: Option<Vec<u8>>,
		digests: Vec<Vec<u8>>,
		tagged: Option<DigestInfo>,
	}

	#[cfg(feature = "colony")]
	wire_sequence!(ColonyProbe { count: plain, note: octets_opt, digests: octets_seq, tagged: ctx(TagNumber::N0) });

	#[cfg(feature = "colony")]
	fn colony_probe() -> ColonyProbe {
		ColonyProbe {
			count: 7,
			note: Some(Vec::from([0xAA, 0xBB])),
			digests: Vec::from([Vec::from([1, 2]), Vec::from([3])]),
			tagged: None,
		}
	}

	// Each field kind decodes again to the value that wrote it, with its
	// optionals present or absent.
	#[cfg(feature = "colony")]
	crate::tb_cases! {
		fn round_trips(original: ColonyProbe) {
			assert_eq!(der_round_trip(&original), original);
		}
		cases {
			all_field_kinds => colony_probe(),
			absent_optionals => ColonyProbe { note: None, digests: Vec::new(), ..colony_probe() },
		}
	}

	#[cfg(feature = "colony")]
	#[derive(Debug, Clone, PartialEq, Eq)]
	struct BudgetProbe {
		budget: u8,
	}

	#[cfg(feature = "colony")]
	const BUDGET_DEFAULT: u8 = 7;

	#[cfg(feature = "colony")]
	wire_sequence!(BudgetProbe { budget: default(BUDGET_DEFAULT) });

	/// A field equal to its default is omitted from the wire, and the decode
	/// restores the default.
	#[cfg(feature = "colony")]
	#[test]
	fn default_field_is_omitted_on_the_wire() -> TestResult {
		let encoded = BudgetProbe { budget: BUDGET_DEFAULT }.to_der()?;
		let decoded = BudgetProbe::from_der(&encoded)?;
		assert_eq!(encoded, [0x30, 0x00]);
		assert_eq!(decoded, BudgetProbe { budget: BUDGET_DEFAULT });
		Ok(())
	}

	/// A field that differs from its default travels on the wire and decodes
	/// back.
	#[cfg(feature = "colony")]
	#[test]
	fn non_default_field_round_trips() {
		let original = BudgetProbe { budget: 5 };
		assert_eq!(der_round_trip(&original), original);
	}

	/// A field present with the value of its default is refused as
	/// non-canonical.
	#[cfg(feature = "colony")]
	#[test]
	fn present_default_value_is_refused_as_noncanonical() {
		// SEQUENCE { INTEGER 7 }: an encoder that breaks ITU-T X.690 § 11.5
		// writes the schema default in place of an omitted field. The module
		// `# Sources` links the recommendation.
		let encoded = [0x30, 0x03, 0x02, 0x01, 0x07];
		let refused = BudgetProbe::from_der(&encoded);
		assert_eq!(der_refusal(refused), Some(ErrorKind::Noncanonical { tag: Tag::Integer }));
	}
}
