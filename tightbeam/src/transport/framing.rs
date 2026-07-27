//! Incremental DER TLV framing shared by the sync and async transport planes.
//!
//! Reading a DER envelope off a byte stream happens in stages: tag octet,
//! first length octet, optional long-form length octets, then content. The
//! classification, canonicality, and reconstruction logic lives here so the
//! planes cannot diverge on wire framing.

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use core::mem;
#[cfg(feature = "std")]
use std::io::ErrorKind;

use crate::transport::error::TransportError;

/// Shape of a DER length field, classified from its first octet.
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

/// Parse a DER length field into its numeric value.
///
/// Returns `None` for non-canonical or indefinite-length encodings.
pub(crate) fn parse_der_length(first_byte: u8, length_octets: &[u8]) -> Option<usize> {
	let octet_count = match LengthForm::from(first_byte) {
		LengthForm::Short(length) => return Some(length),
		LengthForm::Long(count) => count,
	};

	// 0x80 is the BER indefinite-length marker, forbidden in DER.
	if octet_count == 0 || octet_count != length_octets.len() || octet_count > mem::size_of::<usize>() {
		return None;
	}

	// Canonical form: no leading zero octet, and the long form is only used
	// for values the short form cannot express (>= 128).
	if length_octets[0] == 0 {
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

/// Classify a byte-read failure at a frame boundary.
///
/// EOF before the first byte of a frame is the peer hanging up cleanly
/// between messages: [`TransportError::ConnectionClosed`], which
/// `try_read_decoded_envelope` maps to `Ok(None)`. Everything else passes
/// through unchanged.
pub(crate) fn classify_boundary_error(error: TransportError) -> TransportError {
	#[cfg(feature = "std")]
	if matches!(&error, TransportError::IoError(io) if io.kind() == ErrorKind::UnexpectedEof) {
		return TransportError::ConnectionClosed;
	}

	error
}

/// Classify a byte-read failure inside a frame.
///
/// EOF after the frame started is a truncated message, never a clean
/// close: [`TransportError::InvalidMessage`]. Everything else passes
/// through unchanged.
pub(crate) fn classify_truncation_error(error: TransportError) -> TransportError {
	match &error {
		TransportError::ConnectionClosed => TransportError::InvalidMessage,
		#[cfg(feature = "std")]
		TransportError::IoError(io) if io.kind() == ErrorKind::UnexpectedEof => TransportError::InvalidMessage,
		_ => error,
	}
}

/// Reconstruct a full DER encoding from its parsed tag, length, and content parts.
pub(crate) fn reconstruct_der_encoding(tag: u8, length_first: u8, length_octets: &[u8], content: &[u8]) -> Vec<u8> {
	let mut buffer = Vec::with_capacity(2 + length_octets.len() + content.len());
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

	/// (first length octet, remaining octets, expected decode)
	const PARSE_DER_LENGTH_CASES: &[(u8, &[u8], Option<usize>)] = &[
		(0x00, &[], Some(0)),
		(0x7F, &[], Some(127)),
		(0x81, &[0x80], Some(128)),
		(0x81, &[0xFF], Some(255)),
		(0x82, &[0x01, 0x00], Some(256)),
		(0x80, &[], None),
		(0x81, &[0x05], None),
		(0x82, &[0x00, 0x80], None),
		(0x89, &[0x01; 9], None),
		(0x82, &[0x01], None),
		(0x81, &[], None),
	];

	#[test]
	fn parse_der_length_cases() {
		for &(first, rest, expected) in PARSE_DER_LENGTH_CASES {
			assert_eq!(parse_der_length(first, rest), expected);
		}
	}

	/// (first length octet, content length)
	const LENGTH_FORM_SHORT_CASES: &[(u8, usize)] = &[(0x00, 0), (0x7F, 127)];
	/// (first length octet, further length octet count)
	const LENGTH_FORM_LONG_CASES: &[(u8, usize)] = &[(0x80, 0), (0x81, 1), (0x84, 4), (0xFF, 127)];

	#[test]
	fn length_form_classifies_first_octet() {
		for &(first, length) in LENGTH_FORM_SHORT_CASES {
			assert!(matches!(LengthForm::from(first), LengthForm::Short(len) if len == length));
		}
		for &(first, count) in LENGTH_FORM_LONG_CASES {
			assert!(matches!(LengthForm::from(first), LengthForm::Long(len) if len == count));
		}
	}

	#[cfg(feature = "std")]
	#[test]
	fn boundary_classification_maps_eof_to_clean_close() {
		let eof = TransportError::IoError(ErrorKind::UnexpectedEof.into());
		assert!(matches!(classify_boundary_error(eof), TransportError::ConnectionClosed));

		let reset = TransportError::IoError(ErrorKind::ConnectionReset.into());
		assert!(matches!(classify_boundary_error(reset), TransportError::IoError(_)));
	}

	#[test]
	fn truncation_classification_maps_eof_to_invalid_message() {
		assert!(matches!(
			classify_truncation_error(TransportError::ConnectionClosed),
			TransportError::InvalidMessage
		));
		assert!(matches!(
			classify_truncation_error(TransportError::ConnectionFailed),
			TransportError::ConnectionFailed
		));

		#[cfg(feature = "std")]
		{
			let eof = TransportError::IoError(ErrorKind::UnexpectedEof.into());
			assert!(matches!(classify_truncation_error(eof), TransportError::InvalidMessage));
		}
	}

	#[test]
	fn reconstruct_round_trips_short_and_long_form() {
		assert_eq!(
			reconstruct_der_encoding(0x30, 0x02, &[], &[0x01, 0x02]),
			vec![0x30, 0x02, 0x01, 0x02]
		);
		assert_eq!(
			reconstruct_der_encoding(0x30, 0x81, &[0x80], &[0xAA]),
			vec![0x30, 0x81, 0x80, 0xAA]
		);
	}
}
