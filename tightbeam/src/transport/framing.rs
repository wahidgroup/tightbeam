//! Incremental DER TLV framing shared by the sync and async transport planes.
//!
//! A reader takes a DER envelope off a byte stream in stages: the tag octet,
//! the first length octet, any long-form length octets, and then the content.
//! The classification, canonicality, and reconstruction logic lives here, so
//! both planes share one framing of the byte stream.

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use core::mem;
#[cfg(feature = "std")]
use std::io::ErrorKind;

use crate::transport::error::{TransportError, TransportFailure};
use crate::transport::TransportResult;

/// The shape of a DER length field, classified from its first octet.
pub(crate) enum LengthForm {
	/// Short form: the octet itself is the content length.
	Short(usize),
	/// Long form: this many further octets carry the content length.
	Long(usize),
}

impl From<u8> for LengthForm {
	fn from(first_byte: u8) -> Self {
		if first_byte & 0x80 == 0 {
			Self::Short(first_byte as usize)
		} else {
			Self::Long((first_byte & 0x7F) as usize)
		}
	}
}

/// Parses a DER length field into its numeric value.
///
/// Returns `None` for non-canonical or indefinite-length encodings.
fn parse_der_length(first_byte: u8, length_octets: impl AsRef<[u8]>) -> Option<usize> {
	let length_octets = length_octets.as_ref();
	let octet_count = match LengthForm::from(first_byte) {
		LengthForm::Short(length) => return Some(length),
		LengthForm::Long(count) => count,
	};

	// A first octet of 0x80 is the BER indefinite-length marker, which DER
	// forbids.
	if octet_count == 0 || octet_count != length_octets.len() || octet_count > mem::size_of::<usize>() {
		return None;
	}

	// The DER canonical form forbids a leading zero octet, and it permits the
	// long form only for a value the short form cannot express (>= 128).
	if length_octets.first() == Some(&0) {
		return None;
	}

	let mut length = 0usize;
	for &byte in length_octets.iter() {
		length = (length << 8) | (byte as usize);
	}

	if length < 0x80 {
		return None;
	}

	Some(length)
}

/// A DER frame header read from the wire, before the reader allocates any
/// content.
///
/// The declared content length has passed no ceiling check, so its accessor
/// lives on [`AdmittedHeader`] alone.
pub(crate) struct FrameHeader {
	tag: u8,
	length_first: u8,
	length_octets: Vec<u8>,
	declared_len: usize,
}

/// A frame header whose declared length passed a ceiling check.
///
/// [`AdmittedHeader::content_len`] is the only source of a length to allocate
/// with, so no code can size an allocation by an unchecked wire value
/// (CWE-770).
pub(crate) struct AdmittedHeader {
	header: FrameHeader,
}

/// The two leading octets of a DER frame, in the order the link reads them.
///
/// Both are bare octets, so a reader that holds them loose can exchange them
/// and parse a header the peer never sent. The call site binds the named
/// fields, so the exchange has no site at which to occur.
#[derive(Clone, Copy, Debug)]
pub(crate) struct HeaderPrefix {
	/// The identifier octet that names the frame's ASN.1 tag.
	pub(crate) tag: u8,
	/// The first length octet, which decides the short or long form.
	pub(crate) length_first: u8,
}

impl FrameHeader {
	/// Parses a tag and a length field into a header.
	///
	/// # Errors
	///
	/// - [`TransportError::InvalidMessage`] -- the length field is
	///   non-canonical or uses the BER indefinite form.
	pub(crate) fn parse(prefix: HeaderPrefix, length_octets: impl Into<Vec<u8>>) -> TransportResult<Self> {
		let HeaderPrefix { tag, length_first } = prefix;
		let length_octets: Vec<u8> = length_octets.into();
		let declared_len = parse_der_length(length_first, &length_octets).ok_or(TransportError::InvalidMessage)?;
		Ok(Self { tag, length_first, length_octets, declared_len })
	}

	/// Admits this header when its declared length fits within `cap`.
	///
	/// # Errors
	///
	/// - [`TransportFailure::SizeExceeded`] -- the declared length exceeds
	///   `cap`. The refusal comes before the reader reads the content or sizes
	///   a buffer.
	pub(crate) fn admit(self, cap: usize) -> TransportResult<AdmittedHeader> {
		if self.declared_len > cap {
			return Err(TransportError::OperationFailed(TransportFailure::SizeExceeded));
		}

		Ok(AdmittedHeader { header: self })
	}
}

impl AdmittedHeader {
	/// The content length that passed the ceiling check.
	pub(crate) fn content_len(&self) -> usize {
		self.header.declared_len
	}

	/// Rebuilds the complete DER encoding from this header and its content.
	pub(crate) fn reconstruct(&self, content: impl AsRef<[u8]>) -> Vec<u8> {
		let content = content.as_ref();
		reconstruct_der_encoding(self.header.tag, self.header.length_first, &self.header.length_octets, content)
	}
}

impl TransportError {
	/// Classifies a byte-read failure at a frame boundary.
	///
	/// An EOF before the first byte of a frame is a clean hang-up by the peer
	/// between messages. It becomes [`TransportError::ConnectionClosed`],
	/// which `try_read_decoded_envelope` maps to `Ok(None)`. Any other error
	/// passes through unchanged.
	pub(crate) fn at_frame_boundary(self) -> Self {
		#[cfg(feature = "std")]
		if matches!(&self, Self::IoError(io) if io.kind() == ErrorKind::UnexpectedEof) {
			return Self::ConnectionClosed;
		}

		self
	}

	/// Classifies a byte-read failure inside a frame.
	///
	/// An EOF after the frame starts is a truncated message and never a clean
	/// close, so it becomes [`TransportError::InvalidMessage`]. Any other error
	/// passes through unchanged.
	pub(crate) fn inside_frame(self) -> Self {
		match &self {
			Self::ConnectionClosed => Self::InvalidMessage,
			#[cfg(feature = "std")]
			Self::IoError(io) if io.kind() == ErrorKind::UnexpectedEof => Self::InvalidMessage,
			_ => self,
		}
	}
}

/// Reconstructs a full DER encoding from its parsed tag, length, and content
/// parts.
fn reconstruct_der_encoding(
	tag: u8,
	length_first: u8,
	length_octets: impl AsRef<[u8]>,
	content: impl AsRef<[u8]>,
) -> Vec<u8> {
	let length_octets = length_octets.as_ref();
	let content = content.as_ref();
	let header_len = length_octets.len().saturating_add(2);
	let mut buffer = Vec::with_capacity(header_len.saturating_add(content.len()));
	buffer.push(tag);
	buffer.push(length_first);

	if matches!(LengthForm::from(length_first), LengthForm::Long(_)) {
		buffer.extend_from_slice(length_octets);
	}

	buffer.extend_from_slice(content);

	buffer
}

#[cfg(test)]
mod tests {
	use super::*;

	// Each case is (first length octet, remaining octets, expected decode).
	crate::tb_cases! {
		fn parse_der_length_cases((first, rest, expected): (u8, &[u8], Option<usize>)) {
			assert_eq!(parse_der_length(first, rest), expected);
		}
		cases {
			short_zero => (0x00, &[], Some(0)),
			short_most => (0x7F, &[], Some(127)),
			one_octet_least => (0x81, &[0x80], Some(128)),
			one_octet_most => (0x81, &[0xFF], Some(255)),
			two_octets => (0x82, &[0x01, 0x00], Some(256)),
			indefinite => (0x80, &[], None),
			one_octet_in_the_short_range => (0x81, &[0x05], None),
			two_octets_with_a_leading_zero => (0x82, &[0x00, 0x80], None),
			nine_octets => (0x89, &[0x01; 9], None),
			two_octets_with_one_present => (0x82, &[0x01], None),
			one_octet_with_none_present => (0x81, &[], None),
		}
	}

	// Each case is (first length octet, content length).
	crate::tb_cases! {
		fn length_form_classifies_a_short_first_octet((first, length): (u8, usize)) {
			assert!(matches!(LengthForm::from(first), LengthForm::Short(len) if len == length));
		}
		cases {
			zero => (0x00, 0),
			most => (0x7F, 127),
		}
	}

	// Each case is (first length octet, further length octet count).
	crate::tb_cases! {
		fn length_form_classifies_a_long_first_octet((first, count): (u8, usize)) {
			assert!(matches!(LengthForm::from(first), LengthForm::Long(len) if len == count));
		}
		cases {
			indefinite => (0x80, 0),
			one_octet => (0x81, 1),
			four_octets => (0x84, 4),
			most => (0xFF, 127),
		}
	}

	#[cfg(feature = "std")]
	#[test]
	fn boundary_classification_maps_eof_to_clean_close() {
		let eof = TransportError::IoError(ErrorKind::UnexpectedEof.into());
		assert!(matches!((eof).at_frame_boundary(), TransportError::ConnectionClosed));

		let reset = TransportError::IoError(ErrorKind::ConnectionReset.into());
		assert!(matches!((reset).at_frame_boundary(), TransportError::IoError(_)));
	}

	#[test]
	fn truncation_classification_maps_eof_to_invalid_message() {
		assert!(matches!(
			(TransportError::ConnectionClosed).inside_frame(),
			TransportError::InvalidMessage
		));
		assert!(matches!(
			(TransportError::ConnectionFailed).inside_frame(),
			TransportError::ConnectionFailed
		));

		#[cfg(feature = "std")]
		{
			let eof = TransportError::IoError(ErrorKind::UnexpectedEof.into());
			assert!(matches!((eof).inside_frame(), TransportError::InvalidMessage));
		}
	}

	#[test]
	fn reconstruct_round_trips_short_and_long_form() {
		assert_eq!(
			reconstruct_der_encoding(0x30, 0x02, [], [0x01, 0x02]),
			vec![0x30, 0x02, 0x01, 0x02]
		);
		assert_eq!(
			reconstruct_der_encoding(0x30, 0x81, [0x80], [0xAA]),
			vec![0x30, 0x81, 0x80, 0xAA]
		);
	}
}
