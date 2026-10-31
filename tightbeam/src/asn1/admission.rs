//! The admission walk: it checks the DER a peer sent before a typed decode
//! reads it.
//!
//! `der` 0.7 insertion-sorts each `SET OF` it decodes, so a set that arrives
//! in descending order costs quadratic compares before any cap, signature, or
//! tag runs (CWE-407).
//!
//! # Owners
//!
//! Each decoder of peer DER reads every SET it holds through one owner, which
//! runs [`DerAdmission::admit`] on the DER it decodes:
//!
//! | Owner | Rules | What it reads |
//! | --- | --- | --- |
//! | [`WireDer`] | CMS | Each handshake container, the frame envelope, and a receipt's sealed acknowledgement |
//! | [`Signed`](crate::frame::Signed) | CMS | Each signer structure, the client Finished among them |
//! | `AuthEnvelopedData::decode_detached` | CMS | Each session record |
//! | The opened closing of an anonymous client | CMS | Its attribute set |
//! | [`decode`](crate::decode) | A | Each message body |
//! | [`CleartextFrame::decode`] | A ([`DerAdmission::SetOrder`]) | The body of a routed frame |
//! | [`Frame::decode_message`] | A ([`DerAdmission::SetOrder`]) | The body of a borrowed frame |
//! | `Frame::decrypt`, `Frame::open_typed` | A ([`DerAdmission::SetOrder`]) | The body of a frame they open in place |
//! | `CertificateExt::extension` | A | Each extension value |
//!
//! A schema with no SET of its own runs no walk. `Frame`, `Metadata`, and
//! `TransportEnvelope` hold their SETs inside a
//! [`Signed`](crate::frame::Signed) or a [`WireDer`](crate::asn1::WireDer).
//! `ClientHello`, `ServerHandshake`, `OpeningContent`, and `SessionReceipt`
//! hold none.
//!
//! # Arrangement
//!
//! An encoder whose `der` order differs from DER's puts its output in DER
//! order with [`DerAdmission::arrange`], and the IMPLICIT SET OF fields that
//! only its schema names with [`DerAdmission::arrange_fields`].
//!
//! # Arrival
//!
//! Each reader of peer CMS below holds its decoded value to the octets it
//! arrived as with [`DerAdmission::arrived_as`]:
//!
//! - [`WireDer`](crate::asn1::WireDer): each handshake container and the frame envelope.
//! - [`Signed`](crate::frame::Signed): each signer structure.
//! - `AuthEnvelopedData::decode_detached`: each session record.
//! - The view of an envelope that an open reads its attributes through.
//!
//! # Rules
//!
//! - Rule A refuses a universal SET whose elements are out of ascending DER order, or repeat.
//! - Rule B, at the CMS owners, refuses a universal SET or a constructed
//!   context-specific element of more than [`MAX_CMS_SET_LEN`] elements.
//!
//! X.690 § 11.6 orders a SET OF by its encodings, and `der` refuses two equal
//! ones. Where `der` orders a type as DER does, its sort moves no element of
//! an admitted set, so it runs in linear time.
//!
//! `der` orders a CHOICE of CMS, such as a `SignerInfo` or a `RecipientInfo`,
//! another way, and only the schema tells an IMPLICIT SET, such as
//! `certificates`, from an IMPLICIT SEQUENCE. Rule B bounds the sort of either
//! by its length instead.
//!
//! # Scope
//!
//! The walk reads every universal SET as a SET OF. X.690 § 10.3 orders the
//! components of an ASN.1 `SET` by their tags instead, so a consumer type
//! that holds one decodes outside [`decode`](crate::decode). No schema of
//! the crate holds one, and `der` 0.7 derives none.
//!
//! # Cost
//!
//! The walk is one loop with fixed state at any depth. It reads each header
//! once in document order, and once more when it checks its parent's elements.
//!
//! A rule A comparison stops at the first octet that differs, so the
//! comparisons of a value of `n` octets read `O(n log n)` octets at worst,
//! against the `O(n²)` compares of the sort they guard.
//!
//! # Sources
//!
//! - ITU-T X.690 (02/2021) § 8.9.2, sequence components, § 10.3, set
//!   components, § 11.5, components of a default value, and § 11.6, set-of
//!   components:
//!   <https://www.itu.int/rec/dologin_pub.asp?id=T-REC-X.690-202102-I%21%21PDF-E&lang=e&type=items#page=29>
//! - CWE-20, improper input validation: <https://cwe.mitre.org/data/definitions/20.html>
//! - CWE-407, inefficient algorithmic complexity: <https://cwe.mitre.org/data/definitions/407.html>
//!
//! [`WireDer`]: crate::asn1::WireDer
//! [`CleartextFrame::decode`]: crate::router::CleartextFrame::decode
//! [`Frame::decode_message`]: crate::Frame::decode_message

#[cfg(not(feature = "std"))]
use alloc::{vec, vec::Vec};

use core::cmp::Ordering;

use crate::constants::MAX_CMS_SET_LEN;
use crate::der::{
	Decode, EncodeValue, ErrorKind, Header, Reader, Result as DerResult, SliceReader, SliceWriter, Tag, Tagged, Writer,
};

/// A wire value of the crate, the encoding that its house sender writes, and
/// the hold of an arrival to that encoding.
///
/// The provided encoder writes the `der` encoding, which is DER for a type
/// whose every SET `der` orders as DER does. A type whose SET `der` orders
/// otherwise, such as a `SignedData`, writes its own.
pub(crate) trait Canonical: EncodeValue + Tagged {
	/// Write the contents octets of this value, after its tag and length, as
	/// its house sender writes them.
	///
	/// # Errors
	///
	/// - The encode error of the value.
	fn encode_canonical(&self, writer: &mut impl Writer) -> DerResult<()> {
		self.encode_value(writer)
	}

	/// Whether `arrived`, the contents octets that this value decoded from,
	/// are the encoding that [`Self::encode_canonical`] writes. Rule A
	/// admitted `arrived` before the decode.
	///
	/// The provided hold streams that encoding against `arrived`.
	///
	/// # Errors
	///
	/// - The encode error of the value.
	fn is_encoded_as(&self, arrived: &[u8]) -> DerResult<bool> {
		Comparing::is_written_by(arrived, |writer| self.encode_canonical(writer))
	}
}

/// The rules an owner of peer DER applies before its typed decode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DerAdmission {
	/// Rule A: every universal SET holds its elements in DER order.
	SetOrder,
	/// Rules A and B: every universal SET holds its elements in DER order, and
	/// every universal SET and constructed context-specific element holds at
	/// most [`MAX_CMS_SET_LEN`] elements.
	Cms,
}

impl DerAdmission {
	/// Admit `der`, a run of DER elements such as one value or the contents of
	/// one, under these rules.
	///
	/// # Errors
	///
	/// - The header error, or [`ErrorKind::Length`] -- an element is no DER header, or runs past its parent.
	/// - [`ErrorKind::SetOrdering`] -- a universal SET holds an element after one that sorts after it.
	/// - [`ErrorKind::SetDuplicate`] -- a universal SET holds one encoding twice.
	/// - [`ErrorKind::Overlength`] -- under [`Self::Cms`], a universal SET or a
	///   constructed context-specific element holds more than
	///   [`MAX_CMS_SET_LEN`] elements.
	pub(crate) fn admit(self, der: impl AsRef<[u8]>) -> DerResult<()> {
		let der = der.as_ref();
		let mut at = 0usize;
		while let Some(rest) = der.get(at..).filter(|rest| !rest.is_empty()) {
			let element = Element::first(rest)?;

			// A constructed element continues the walk at its first element,
			// so the walk meets every header in document order. The check of
			// its elements already proved that they fill it exactly.
			let step = if element.tag.is_constructed() {
				self.admit_elements(&element)?;
				element.header_len
			} else {
				element.encoding.len()
			};

			at = at.checked_add(step).ok_or(ErrorKind::Overflow)?;
		}

		Ok(())
	}

	/// Decode `der`, one DER value, as `T` once these rules admit it, so every
	/// decoder of peer DER runs the walk before the decode sorts a SET.
	///
	/// # Errors
	///
	/// - The errors of [`Self::admit`].
	/// - The decode error of `T`, or [`ErrorKind::TrailingData`] -- `der` is no single `T`.
	pub(crate) fn decode<'a, T: Decode<'a>>(self, der: &'a [u8]) -> DerResult<T> {
		self.admit(der)?;
		T::from_der(der)
	}

	/// Check the elements of the constructed `parent` against these rules,
	/// and check that they fill its contents exactly.
	///
	/// # Errors
	///
	/// - The errors of [`Self::admit`], for the elements of `parent` alone.
	fn admit_elements(self, parent: &Element<'_>) -> DerResult<()> {
		let is_set = parent.tag == Tag::Set;
		let is_capped = self == Self::Cms && (is_set || parent.tag.is_context_specific());

		let mut previous: Option<&[u8]> = None;
		for (count, element) in Run(parent.contents()).enumerate() {
			let element = element?;
			if is_capped && count >= MAX_CMS_SET_LEN {
				return Err(ErrorKind::Overlength.into());
			}

			// DER encodings delimit themselves, so neither of two encodings
			// is a prefix of the other, and their octet order is the padded
			// order of X.690 § 11.6.
			if let Some(previous) = previous.filter(|_| is_set) {
				match previous.cmp(element.encoding) {
					Ordering::Less => {}
					Ordering::Equal => return Err(ErrorKind::SetDuplicate.into()),
					Ordering::Greater => return Err(ErrorKind::SetOrdering.into()),
				}
			}

			previous = Some(element.encoding);
		}

		Ok(())
	}

	/// Hold `value` to `arrived`, the contents octets it decoded from, so a
	/// value decodes only from its DER (X.690 § 8.9.2, § 11.5).
	///
	/// - `der` 0.7 skips a context-specific element whose number is below the
	///   one a field looks for, so a decoded value can name less than it
	///   arrived as.
	/// - The compare is the [`Canonical::is_encoded_as`] of the type of `value`.
	///
	/// # Errors
	///
	/// - [`ErrorKind::Noncanonical`] -- `arrived` is another encoding than the canonical one of `value`.
	/// - The encode error of `value`.
	pub(crate) fn arrived_as(value: &impl Canonical, arrived: &[u8]) -> DerResult<()> {
		if !value.is_encoded_as(arrived)? {
			return Err(value.tag().non_canonical_error());
		}

		Ok(())
	}

	/// Put the elements of every universal SET of `der` in the DER order that
	/// rule A admits, in place.
	///
	/// `der` 0.7 sorts a SET OF a CHOICE, such as the `SignerInfos` of a
	/// countersigned `SignedData`, in another order than X.690 § 11.6. A SET
	/// inside an element changes the octets of that element, so the passes
	/// repeat until one moves no element.
	///
	/// # Errors
	///
	/// - The header error, or [`ErrorKind::Length`] -- an element is no DER header, or runs past its parent.
	/// - [`ErrorKind::Overflow`] -- an element runs past `der`.
	pub(crate) fn arrange(der: &mut [u8]) -> DerResult<()> {
		while Self::arrange_pass(der)? {}
		Ok(())
	}

	/// Put the elements of each element of `fields`, a run of DER elements,
	/// whose tag is one of `sets` in DER order, in place.
	///
	/// Only a schema tells an IMPLICIT SET OF, such as the `certificates` of
	/// a `SignedData`, from an IMPLICIT SEQUENCE, so its encoder names the
	/// tags of its SET OF fields here.
	///
	/// # Errors
	///
	/// - The errors of [`Self::arrange`].
	pub(crate) fn arrange_fields(fields: &mut [u8], sets: &[Tag]) -> DerResult<()> {
		let mut at = 0usize;
		while let Some(rest) = fields.get(at..).filter(|rest| !rest.is_empty()) {
			let element = Element::first(rest)?;
			let (tag, header_len, len) = (element.tag, element.header_len, element.encoding.len());
			if sets.contains(&tag) {
				let start = at.checked_add(header_len).ok_or(ErrorKind::Overflow)?;
				let end = at.checked_add(len).ok_or(ErrorKind::Overflow)?;
				let contents = fields.get_mut(start..end).ok_or(ErrorKind::Overflow)?;
				Element::sort_run(contents)?;
			}

			at = at.checked_add(len).ok_or(ErrorKind::Overflow)?;
		}

		Ok(())
	}

	/// Write the contents octets of `value` to `writer` in DER order: every
	/// universal SET, as [`Self::arrange`] puts it, and the elements of each
	/// field whose tag is one of `sets`, as [`Self::arrange_fields`] puts them.
	///
	/// The contents pass through one buffer of their length.
	///
	/// # Errors
	///
	/// - The encode error of `value`.
	/// - The errors of [`Self::arrange`].
	pub(crate) fn write_arranged(value: &impl EncodeValue, sets: &[Tag], writer: &mut impl Writer) -> DerResult<()> {
		let contents_len = usize::try_from(value.value_len()?)?;
		let mut contents = vec![0u8; contents_len];

		let mut contents_writer = SliceWriter::new(&mut contents);
		value.encode_value(&mut contents_writer)?;

		let written = contents_writer.finish()?.len();
		contents.truncate(written);

		Self::arrange(&mut contents)?;
		Self::arrange_fields(&mut contents, sets)?;
		writer.write(&contents)
	}

	/// Sort the elements of each universal SET of `der` once, in document
	/// order, and report whether an element moved.
	///
	/// # Errors
	///
	/// - The errors of [`Self::arrange`].
	fn arrange_pass(der: &mut [u8]) -> DerResult<bool> {
		let mut moved = false;
		let mut at = 0usize;
		while let Some(rest) = der.get(at..).filter(|rest| !rest.is_empty()) {
			let element = Element::first(rest)?;
			let (tag, header_len, len) = (element.tag, element.header_len, element.encoding.len());
			if tag == Tag::Set {
				let start = at.checked_add(header_len).ok_or(ErrorKind::Overflow)?;
				let end = at.checked_add(len).ok_or(ErrorKind::Overflow)?;
				let contents = der.get_mut(start..end).ok_or(ErrorKind::Overflow)?;
				moved |= Element::sort_run(contents)?;
			}

			let step = if tag.is_constructed() {
				header_len
			} else {
				len
			};

			at = at.checked_add(step).ok_or(ErrorKind::Overflow)?;
		}

		Ok(moved)
	}
}

/// One DER element as it arrived: its tag, and its encoding whole.
struct Element<'a> {
	tag: Tag,
	/// The header and the contents.
	encoding: &'a [u8],
	/// The length of the header, where the contents start.
	header_len: usize,
}

impl<'a> Element<'a> {
	/// The element that `bytes` starts with.
	///
	/// # Errors
	///
	/// - The header error -- `bytes` starts with no DER header.
	/// - [`ErrorKind::Length`] -- the contents run past `bytes`.
	fn first(bytes: &'a [u8]) -> DerResult<Self> {
		let mut reader = SliceReader::new(bytes)?;
		let header = Header::decode(&mut reader)?;
		let header_len = usize::try_from(reader.position())?;
		let contents_len = usize::try_from(header.length)?;

		let len = header_len.checked_add(contents_len).ok_or(ErrorKind::Overflow)?;
		let encoding = bytes.get(..len).ok_or_else(|| header.tag.length_error())?;
		Ok(Self { tag: header.tag, encoding, header_len })
	}

	/// The contents octets, after the header.
	fn contents(&self) -> &'a [u8] {
		self.encoding.get(self.header_len..).unwrap_or_default()
	}

	/// Sort the run of elements that fills `run` by their octets, in place,
	/// and report whether an element moved. A run in order allocates nothing.
	///
	/// # Errors
	///
	/// - The errors of [`Self::first`], for each element of `run`.
	fn sort_run(run: &mut [u8]) -> DerResult<bool> {
		if Self::is_sorted_run(run)? {
			return Ok(false);
		}

		let elements = Run(run).map(|element| element.map(|element| element.encoding));
		let mut elements = elements.collect::<DerResult<Vec<&[u8]>>>()?;
		elements.sort_unstable();
		let sorted = elements.concat();
		run.copy_from_slice(&sorted);
		Ok(true)
	}

	/// Whether the elements of `run` are in octet order.
	///
	/// # Errors
	///
	/// - The errors of [`Self::first`], for each element of `run`.
	fn is_sorted_run(run: &[u8]) -> DerResult<bool> {
		let mut previous: Option<&[u8]> = None;
		for element in Run(run) {
			let encoding = element?.encoding;
			if previous.is_some_and(|previous| previous > encoding) {
				return Ok(false);
			}

			previous = Some(encoding);
		}

		Ok(true)
	}
}

/// The elements of a run that fills a buffer, each as it arrived, in order.
struct Run<'a>(&'a [u8]);

impl<'a> Iterator for Run<'a> {
	type Item = DerResult<Element<'a>>;

	fn next(&mut self) -> Option<Self::Item> {
		if self.0.is_empty() {
			return None;
		}

		// A failed read ends the run, so its error is the last item.
		let element = Element::first(self.0);
		self.0 = match &element {
			Ok(element) => self.0.get(element.encoding.len()..).unwrap_or_default(),
			Err(_) => &[],
		};
		Some(element)
	}
}

/// A [`Writer`] that compares the octets an encoder writes with the octets
/// it expects, run by run, and holds no copy of them.
pub(crate) struct Comparing<'a> {
	/// The expected octets the encoder has yet to write, or `None` once a run
	/// differs from them.
	rest: Option<&'a [u8]>,
}

impl<'a> Comparing<'a> {
	/// Whether `encode` writes exactly `expected`, compared as it writes.
	///
	/// # Errors
	///
	/// - The error of `encode`.
	pub(crate) fn is_written_by(
		expected: &'a [u8],
		encode: impl FnOnce(&mut Self) -> DerResult<()>,
	) -> DerResult<bool> {
		let mut comparing = Self { rest: Some(expected) };
		encode(&mut comparing)?;
		Ok(comparing.is_spent())
	}

	/// Whether the encoder wrote exactly the expected octets.
	fn is_spent(&self) -> bool {
		self.rest.is_some_and(<[u8]>::is_empty)
	}
}

impl Writer for Comparing<'_> {
	fn write(&mut self, slice: &[u8]) -> DerResult<()> {
		self.rest = self.rest.and_then(|rest| rest.strip_prefix(slice));
		Ok(())
	}
}

/// The DER the owner tests of the walk build.
#[cfg(test)]
pub(crate) mod fixtures {
	use crate::der::asn1::ObjectIdentifier;
	use crate::der::{Encode, ErrorKind, Header, Length, Result as DerResult, Tag};

	use super::{Element, Run};

	/// The number of elements in every descending set an owner test sends. At
	/// four thousand, the quadratic sort is measurable.
	pub(crate) const DESCENDING_LEN: u16 = 4_000;

	/// The DER of one element of `tag` around `contents`.
	pub(crate) fn tlv(tag: Tag, contents: &[u8]) -> Vec<u8> {
		let length = Length::try_from(contents.len()).expect("a test element fits a DER length");
		let header = Header::new(tag, length).expect("a test header encodes");
		let mut encoding = header.to_der().expect("a test header encodes");
		encoding.extend_from_slice(contents);
		encoding
	}

	/// The elements inside the constructed element that `der` starts with,
	/// each as it arrived: its header and its contents.
	pub(crate) fn elements_of(der: impl AsRef<[u8]>) -> Vec<Vec<u8>> {
		let element = Element::first(der.as_ref()).expect("a test encoding starts with a whole element");
		let children = Run(element.contents()).map(|read| read.map(|child| child.encoding.to_vec()));
		let children = children.collect::<DerResult<_>>();
		children.expect("the contents of a test element are DER elements")
	}

	/// The kind of the DER error that `result` holds, or `None` when it holds
	/// a value.
	pub(crate) fn der_refusal<T>(result: DerResult<T>) -> Option<ErrorKind> {
		result.err().map(|error| error.kind())
	}

	/// A universal SET OF `count` two-octet OCTET STRING values, in ascending
	/// order.
	pub(crate) fn ascending_set_of(count: usize) -> Vec<u8> {
		let value = |value: usize| u16::try_from(value).expect("a test count fits a u16").to_be_bytes();
		let values = (0..count).map(|count| tlv(Tag::OctetString, &value(count)));
		tlv(Tag::Set, &values.collect::<Vec<_>>().concat())
	}

	/// The contents of a SET OF `count` two-octet OCTET STRING values, in
	/// descending order.
	pub(crate) fn descending_values(count: u16) -> Vec<u8> {
		let values = (0..count).rev().map(|value| tlv(Tag::OctetString, &value.to_be_bytes()));
		values.collect::<Vec<_>>().concat()
	}

	/// A universal SET OF [`DESCENDING_LEN`] values in descending order.
	pub(crate) fn descending_set() -> Vec<u8> {
		tlv(Tag::Set, &descending_values(DESCENDING_LEN))
	}

	/// The DER of an `Attribute` whose values are [`descending_set`], which
	/// `der` decodes and sorts.
	pub(crate) fn descending_attribute() -> Vec<u8> {
		let oid = ObjectIdentifier::new_unwrap("1.2.3.4");
		let oid = oid.to_der().expect("a test OID encodes");
		tlv(Tag::Sequence, &[oid, descending_set()].concat())
	}
}

#[cfg(test)]
mod tests {
	use crate::der::asn1::OctetString;
	use crate::der::TagNumber;
	use crate::testing::TestResult;

	use super::fixtures::{ascending_set_of, der_refusal, descending_set, tlv};
	use super::*;

	/// A SET OF three values in ascending order.
	fn ascending_set() -> Vec<u8> {
		tlv(Tag::Set, &[0x04, 0x01, 0x01, 0x04, 0x01, 0x02, 0x04, 0x01, 0x03])
	}

	/// A constructed `[0]` of `count` NULL elements.
	fn tagged_of(count: usize) -> Vec<u8> {
		let tag = Tag::ContextSpecific { constructed: true, number: TagNumber::N0 };
		tlv(tag, &[0x05, 0x00].repeat(count))
	}

	/// A [`descending_set`] in a SEQUENCE, in a constructed `[3]`, in a
	/// SEQUENCE.
	fn nested_descending_set() -> Vec<u8> {
		let tag = Tag::ContextSpecific { constructed: true, number: TagNumber::N3 };
		tlv(Tag::Sequence, &tlv(tag, &tlv(Tag::Sequence, &descending_set())))
	}

	// The walk admits the DER its rules accept, and refuses the rest with the
	// kind of the rule it breaks.
	crate::tb_cases! {
		fn the_walk_holds_der_to_its_rules((rules, der, expected): (DerAdmission, Vec<u8>, Option<ErrorKind>)) {
			assert_eq!(der_refusal(rules.admit(der)), expected);
		}
		cases {
			a_set_in_der_order => (DerAdmission::SetOrder, ascending_set(), None),
			a_descending_set => (DerAdmission::SetOrder, descending_set(), Some(ErrorKind::SetOrdering)),
			a_set_that_repeats_an_encoding => (
				DerAdmission::SetOrder,
				tlv(Tag::Set, &[0x04, 0x01, 0x01, 0x04, 0x01, 0x01]),
				Some(ErrorKind::SetDuplicate),
			),
			/// The walk reaches a set at any depth, inside sequences and tagged
			/// elements.
			a_nested_descending_set => (DerAdmission::SetOrder, nested_descending_set(), Some(ErrorKind::SetOrdering)),
			/// The contents of an OCTET STRING may be ciphertext, so the owner
			/// that decodes them walks them.
			the_contents_of_an_octet_string => (DerAdmission::SetOrder, tlv(Tag::OctetString, &descending_set()), None),
			a_tagged_element_at_the_cap => (DerAdmission::Cms, tagged_of(MAX_CMS_SET_LEN), None),
			a_tagged_element_past_the_cap => (
				DerAdmission::Cms,
				tagged_of(MAX_CMS_SET_LEN + 1),
				Some(ErrorKind::Overlength),
			),
			/// `der` sorts a SET OF a CHOICE of CMS in another order than
			/// DER's, so rule B bounds a universal SET at the CMS owners too.
			a_universal_set_past_the_cap_under_cms => (
				DerAdmission::Cms,
				ascending_set_of(MAX_CMS_SET_LEN + 1),
				Some(ErrorKind::Overlength),
			),
			/// Rule B binds the CMS owners alone.
			a_tagged_element_past_the_cap_under_set_order => (
				DerAdmission::SetOrder,
				tagged_of(MAX_CMS_SET_LEN + 1),
				None,
			),
			/// An element whose length runs past its parent is refused at the
			/// parent, before the walk reads into it.
			an_element_past_its_parent => (
				DerAdmission::SetOrder,
				vec![0x30, 0x03, 0x30, 0x05, 0x05, 0x00, 0x05, 0x00],
				Some(ErrorKind::Length { tag: Tag::Sequence }),
			),
		}
	}

	/// A set of a CHOICE that `der` sorts in another order than DER's goes
	/// out in DER's.
	#[test]
	fn a_set_out_of_der_order_is_arranged_into_it() -> TestResult {
		let mut arranged = tlv(Tag::Set, &[0x04, 0x01, 0x02, 0x04, 0x01, 0x01]);

		DerAdmission::arrange(&mut arranged)?;
		assert_eq!(arranged, tlv(Tag::Set, &[0x04, 0x01, 0x01, 0x04, 0x01, 0x02]));
		Ok(())
	}

	/// The arrangement of a set inside an element of another set changes the
	/// octets of that element, here from after its sibling to before it, so
	/// the outer set is arranged again.
	#[test]
	fn a_set_is_arranged_after_the_sets_inside_it() -> TestResult {
		let first_once_sorted = tlv(Tag::Sequence, &tlv(Tag::Set, &[0x04, 0x01, 0x03, 0x04, 0x01, 0x01]));
		let sibling = tlv(Tag::Sequence, &tlv(Tag::Set, &[0x04, 0x01, 0x02, 0x04, 0x01, 0x05]));
		let mut nested = tlv(Tag::Set, &[first_once_sorted, sibling.clone()].concat());

		DerAdmission::arrange(&mut nested)?;

		let first_sorted = tlv(Tag::Sequence, &tlv(Tag::Set, &[0x04, 0x01, 0x01, 0x04, 0x01, 0x03]));
		assert_eq!(nested, tlv(Tag::Set, &[first_sorted, sibling].concat()));
		Ok(())
	}

	/// An OCTET STRING is its contents octets in DER.
	impl Canonical for OctetString {}

	/// The refusal of an arrival in another encoding than its value's.
	const NONCANONICAL: Option<ErrorKind> = Some(ErrorKind::Noncanonical { tag: Tag::OctetString });

	// The hold of a value to its arrival admits the canonical encoding of the
	// value alone.
	crate::tb_cases! {
		fn an_arrival_is_held_to_the_canonical_encoding((arrived, expected): (&[u8], Option<ErrorKind>)) -> TestResult {
			let value = OctetString::new(b"abc")?;
			assert_eq!(der_refusal(DerAdmission::arrived_as(&value, arrived)), expected);
			Ok(())
		}
		cases {
			equal_to_it => (b"abc", None),
			differing_in_its_last_octet => (b"abx", NONCANONICAL),
			running_past_it => (b"abc\x00", NONCANONICAL),
			ending_short_of_it => (b"ab", NONCANONICAL),
		}
	}
}
