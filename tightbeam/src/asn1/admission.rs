//! The admission walk, which checks the DER a peer sent before a typed decode
//! reads it.
//!
//! The pinned `der` 0.7 decoder sorts each `SET OF` it decodes with an
//! insertion sort, so a set that arrives in descending order costs compares
//! quadratic in its length, before any cap, signature, or tag runs (CWE-407).
//!
//! # Owners
//!
//! Each owner below runs [`DerAdmission::admit`] on the DER it decodes, and
//! each decoder of peer DER reads every SET it holds through one of them:
//!
//! - [`WireDer`](crate::asn1::WireDer), under the CMS rules: each handshake
//!   container, the frame envelope, and the sealed acknowledgement of a
//!   receipt.
//! - [`Signed`](crate::frame::Signed), under the CMS rules: each signer
//!   structure, the client Finished among them.
//! - `AuthEnvelopedData::decode_detached`, under the CMS rules: each session record.
//! - The opened closing of an anonymous client, under the CMS rules: its attribute set.
//! - [`decode`](crate::decode), under rule A: each message body.
//! - [`CleartextFrame::decode`](crate::router::CleartextFrame::decode) walks
//!   the body of a routed frame under [`DerAdmission::SetOrder`] before its
//!   typed decode.
//! - `CertificateExt::extension`, under rule A: each extension value.
//!
//! A decoder of a schema that holds no SET of its own runs no walk:
//!
//! - `Frame`, `Metadata`, and `TransportEnvelope` hold each of their SETs
//!   inside a [`Signed`](crate::frame::Signed) or a
//!   [`WireDer`](crate::asn1::WireDer).
//! - `ClientHello`, `ServerHandshake`, `OpeningContent`, and `SessionReceipt` hold none.
//!
//! # Arrangement
//!
//! An encoder whose `der` order differs from DER's puts its output in DER
//! order with [`DerAdmission::arrange`], and the IMPLICIT SET OF fields that
//! only its schema names with [`DerAdmission::arrange_fields`].
//!
//! # Rules
//!
//! - Rule A refuses a universal SET whose elements are not in ascending DER
//!   order, or that holds one encoding twice.
//! - Rule B, at the CMS owners, refuses a universal SET or a constructed
//!   context-specific element of more than [`MAX_CMS_SET_LEN`] elements.
//!
//! X.690 § 11.6 orders the elements of a SET OF by their encodings, and
//! `der`'s own decode of a `SET OF` refuses two equal ones. Where `der`
//! orders a type as DER does, the sort swaps no element of an admitted set,
//! so it reads the set in linear time.
//!
//! `der` orders a CHOICE of CMS, such as a `SignerInfo` or a `RecipientInfo`,
//! in another order, and only the schema tells an IMPLICIT SET, such as
//! `certificates`, from an IMPLICIT SEQUENCE. Rule B bounds the sort of either
//! set by its length instead.
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
//! The walk is one loop, and it holds a fixed amount of state at any depth. It
//! reads each header once in document order, and once more when it checks the
//! elements of the constructed element that holds it.
//!
//! A comparison of rule A stops at the first octet that differs, so it reads
//! at most the octets of the shorter element. The comparisons of a value of
//! `n` octets therefore read `O(n log n)` octets in the worst case, against
//! the `O(n²)` compares of the sort they guard.
//!
//! # Sources
//!
//! - ITU-T X.690 (02/2021) § 10.3, set components, and § 11.6, set-of components:
//!   <https://www.itu.int/rec/dologin_pub.asp?id=T-REC-X.690-202102-I%21%21PDF-E&lang=e&type=items#page=29>
//! - CWE-407, inefficient algorithmic complexity: <https://cwe.mitre.org/data/definitions/407.html>

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use core::cmp::Ordering;

use crate::constants::MAX_CMS_SET_LEN;
use crate::der::{Decode, ErrorKind, Header, Reader, Result as DerResult, SliceReader, Tag};

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

/// The DER the owner tests of the walk build.
#[cfg(test)]
pub(crate) mod fixtures {
	use crate::der::asn1::ObjectIdentifier;
	use crate::der::{Encode, Header, Length, Tag};

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
	use super::fixtures::{descending_set, tlv};
	use super::*;
	use crate::der::TagNumber;

	/// The error kind `admit` returns for `der` under `rules`.
	fn refusal(rules: DerAdmission, der: &[u8]) -> Option<ErrorKind> {
		rules.admit(der).err().map(|error| error.kind())
	}

	/// A SET OF three values in ascending order.
	fn ascending_set() -> Vec<u8> {
		tlv(Tag::Set, &[0x04, 0x01, 0x01, 0x04, 0x01, 0x02, 0x04, 0x01, 0x03])
	}

	/// A universal SET of `count` OCTET STRING values in ascending order.
	fn ascending_set_of(count: usize) -> Vec<u8> {
		let value = |value: usize| u16::try_from(value).expect("a test count fits a u16").to_be_bytes();
		let values = (0..count).map(|count| tlv(Tag::OctetString, &value(count)));
		tlv(Tag::Set, &values.collect::<Vec<_>>().concat())
	}

	/// A constructed `[0]` of `count` NULL elements.
	fn tagged_of(count: usize) -> Vec<u8> {
		let tag = Tag::ContextSpecific { constructed: true, number: TagNumber::N0 };
		tlv(tag, &[0x05, 0x00].repeat(count))
	}

	#[test]
	fn a_set_in_der_order_is_admitted() -> DerResult<()> {
		DerAdmission::SetOrder.admit(ascending_set())?;
		Ok(())
	}

	#[test]
	fn a_descending_set_is_refused() {
		assert_eq!(refusal(DerAdmission::SetOrder, &descending_set()), Some(ErrorKind::SetOrdering));
	}

	#[test]
	fn a_set_that_repeats_an_encoding_is_refused() {
		let repeated = tlv(Tag::Set, &[0x04, 0x01, 0x01, 0x04, 0x01, 0x01]);
		assert_eq!(refusal(DerAdmission::SetOrder, &repeated), Some(ErrorKind::SetDuplicate));
	}

	/// The walk reaches a set at any depth, inside sequences and tagged
	/// elements.
	#[test]
	fn a_nested_descending_set_is_refused() {
		let tag = Tag::ContextSpecific { constructed: true, number: TagNumber::N3 };
		let nested = tlv(Tag::Sequence, &tlv(tag, &tlv(Tag::Sequence, &descending_set())));
		assert_eq!(refusal(DerAdmission::SetOrder, &nested), Some(ErrorKind::SetOrdering));
	}

	/// The contents of an OCTET STRING may be ciphertext, so the owner that
	/// decodes them walks them.
	#[test]
	fn the_contents_of_an_octet_string_are_admitted_as_octets() -> DerResult<()> {
		let wrapped = tlv(Tag::OctetString, &descending_set());
		DerAdmission::SetOrder.admit(wrapped)?;
		Ok(())
	}

	#[test]
	fn a_tagged_element_at_the_cap_is_admitted() -> DerResult<()> {
		DerAdmission::Cms.admit(tagged_of(MAX_CMS_SET_LEN))?;
		Ok(())
	}

	#[test]
	fn a_tagged_element_past_the_cap_is_refused() {
		let past = tagged_of(MAX_CMS_SET_LEN + 1);
		assert_eq!(refusal(DerAdmission::Cms, &past), Some(ErrorKind::Overlength));
	}

	/// `der` sorts a SET OF a CHOICE of CMS in another order than DER's, so
	/// rule B bounds a universal SET at the CMS owners too.
	#[test]
	fn a_universal_set_past_the_cap_is_refused_under_cms() {
		let past = ascending_set_of(MAX_CMS_SET_LEN + 1);
		assert_eq!(refusal(DerAdmission::Cms, &past), Some(ErrorKind::Overlength));
	}

	/// Rule B binds the CMS owners alone.
	#[test]
	fn a_tagged_element_past_the_cap_is_admitted_under_set_order() -> DerResult<()> {
		DerAdmission::SetOrder.admit(tagged_of(MAX_CMS_SET_LEN + 1))?;
		Ok(())
	}

	/// A set of a CHOICE that `der` sorts in another order than DER's goes
	/// out in DER's.
	#[test]
	fn a_set_out_of_der_order_is_arranged_into_it() -> DerResult<()> {
		let mut arranged = tlv(Tag::Set, &[0x04, 0x01, 0x02, 0x04, 0x01, 0x01]);

		DerAdmission::arrange(&mut arranged)?;
		assert_eq!(arranged, tlv(Tag::Set, &[0x04, 0x01, 0x01, 0x04, 0x01, 0x02]));
		Ok(())
	}

	/// The arrangement of a set inside an element of another set changes the
	/// octets of that element, here from after its sibling to before it, so
	/// the outer set is arranged again.
	#[test]
	fn a_set_is_arranged_after_the_sets_inside_it() -> DerResult<()> {
		let first_once_sorted = tlv(Tag::Sequence, &tlv(Tag::Set, &[0x04, 0x01, 0x03, 0x04, 0x01, 0x01]));
		let sibling = tlv(Tag::Sequence, &tlv(Tag::Set, &[0x04, 0x01, 0x02, 0x04, 0x01, 0x05]));
		let mut nested = tlv(Tag::Set, &[first_once_sorted, sibling].concat());

		DerAdmission::arrange(&mut nested)?;
		DerAdmission::SetOrder.admit(nested)?;
		Ok(())
	}

	/// An element whose length runs past its parent is refused at the parent,
	/// before the walk reads into it.
	#[test]
	fn an_element_past_its_parent_is_refused() {
		let overrun = [0x30, 0x03, 0x30, 0x05, 0x05, 0x00, 0x05, 0x00];
		let past_parent = ErrorKind::Length { tag: Tag::Sequence };
		assert_eq!(refusal(DerAdmission::SetOrder, &overrun), Some(past_parent));
	}
}
