//! Incremental DER TLV framing shared by the sync and async transport planes.
//!
//! A reader takes a DER envelope off a byte stream in stages: the tag octet,
//! the first length octet, any long-form length octets, and then the content.
//! [`FrameAssembler`] holds the stage order, the canonicality check, and the
//! cap, so both planes share one framing of the byte stream.

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use core::mem;
#[cfg(feature = "std")]
use std::io::ErrorKind;

use crate::transport::error::{TransportError, TransportFailure};
use crate::transport::TransportResult;

/// The octets a frame buffer holds before its content: the tag, the first
/// length octet, and the longest length field a `usize` holds.
const HEADER_CAPACITY: usize = mem::size_of::<usize>().saturating_add(2);

/// The shape of a DER length field, classified from its first octet.
///
/// A long form counts from one octet up to as many as a `usize` holds, so a
/// length field that classifies fits [`HEADER_CAPACITY`].
enum LengthForm {
	/// Short form: the octet itself is the content length.
	Short(usize),
	/// Long form: this many further octets carry the content length.
	Long(usize),
}

impl TryFrom<u8> for LengthForm {
	type Error = TransportError;

	/// # Errors
	///
	/// - [`TransportError::InvalidMessage`] -- the octet names the BER
	///   indefinite form, or more length octets than a `usize` holds.
	fn try_from(first_byte: u8) -> TransportResult<Self> {
		if first_byte & 0x80 == 0 {
			return Ok(Self::Short(usize::from(first_byte)));
		}

		// A first octet of 0x80 is the BER indefinite-length marker, which DER
		// forbids.
		let count = usize::from(first_byte & 0x7F);
		if count == 0 || count > mem::size_of::<usize>() {
			return Err(TransportError::InvalidMessage);
		}

		Ok(Self::Long(count))
	}
}

/// Parses a DER length field into its numeric value.
///
/// Returns `None` for a first octet that [`LengthForm`] refuses, and for a
/// non-canonical encoding.
fn parse_der_length(first_byte: u8, length_octets: impl AsRef<[u8]>) -> Option<usize> {
	let length_octets = length_octets.as_ref();
	// The parse answers every refusal as `None`, the refusal of the first
	// octet among them.
	let octet_count = match LengthForm::try_from(first_byte).ok()? {
		LengthForm::Short(length) => return Some(length),
		LengthForm::Long(count) => count,
	};

	if octet_count != length_octets.len() {
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
struct FrameHeader {
	declared_len: usize,
}

/// A frame header whose declared length passed a ceiling check.
///
/// [`AdmittedHeader::content_len`] is the only source of a length to allocate
/// with, so no code can size an allocation by an unchecked wire value
/// (CWE-770).
struct AdmittedHeader {
	header: FrameHeader,
}

impl FrameHeader {
	/// Parses a length field, its first octet `length_first` and its
	/// long-form `length_octets`, into a header.
	///
	/// # Errors
	///
	/// - [`TransportError::InvalidMessage`] -- the length field is
	///   non-canonical or uses the BER indefinite form.
	fn parse(length_first: u8, length_octets: impl AsRef<[u8]>) -> TransportResult<Self> {
		let declared_len = parse_der_length(length_first, length_octets).ok_or(TransportError::InvalidMessage)?;
		Ok(Self { declared_len })
	}

	/// Admits this header when its declared length fits within `cap`.
	///
	/// # Errors
	///
	/// - [`TransportFailure::SizeExceeded`] -- the declared length exceeds
	///   `cap`. The refusal comes before the reader reads the content or sizes
	///   a buffer.
	fn admit(self, cap: usize) -> TransportResult<AdmittedHeader> {
		if self.declared_len > cap {
			return Err(TransportError::OperationFailed(TransportFailure::SizeExceeded));
		}

		Ok(AdmittedHeader { header: self })
	}
}

impl AdmittedHeader {
	/// The content length that passed the ceiling check.
	fn content_len(&self) -> usize {
		self.header.declared_len
	}
}

/// The one sequence that takes each DER frame off a byte stream, which both
/// planes drive with the reads of their own streams:
///
/// - Each read fills the region [`Self::wanted`] lends, in the buffer the frame assembles in.
/// - [`Self::advance`] moves the stage, and the cap admits the declared length before the content (CWE-770).
/// - A whole frame returns the assembler to the tag of the next frame, with nothing accepted.
/// - [`Self::classify`] names an end of stream by the stage it interrupts.
pub(crate) struct FrameAssembler {
	cap: usize,
	frame: Vec<u8>,
	/// The octets of `frame` that the stages before this one accepted.
	accepted: usize,
	stage: Stage,
}

/// The part of a frame the assembler reads next.
///
/// The admitted header lives in the stage of the content alone, which the cap
/// check enters.
enum Stage {
	/// The tag octet. An end of stream here falls between two frames.
	Prefix,
	/// The first length octet, after the tag.
	Length,
	/// The long-form length octets, as many as the first length octet named.
	LongLength { octets: usize },
	/// The content of the header that the cap admitted.
	Content { header: AdmittedHeader },
}

impl Stage {
	/// The count of octets this stage reads.
	fn wanted(&self) -> usize {
		match self {
			Self::Prefix | Self::Length => 1,
			Self::LongLength { octets } => *octets,
			Self::Content { header } => header.content_len(),
		}
	}
}

/// What one read gives a [`FrameAssembler`].
pub(crate) enum Step {
	/// The frame wants more octets, which [`FrameAssembler::wanted`] lends.
	More,
	/// The frame is whole, as the DER it arrived as, and the assembler wants
	/// the tag of the next frame.
	Done(Vec<u8>),
}

impl FrameAssembler {
	/// An assembler of the frames of one stream, each of whose declared
	/// content lengths must fit `cap`.
	pub(crate) fn new(cap: usize) -> Self {
		let frame = Vec::with_capacity(HEADER_CAPACITY);
		Self { cap, frame, accepted: 0, stage: Stage::Prefix }
	}

	/// The region that the next read fills: exactly the octets the frame
	/// wants next, in the buffer the frame assembles in.
	pub(crate) fn wanted(&mut self) -> &mut [u8] {
		let end = self.accepted.saturating_add(self.stage.wanted());
		self.frame.resize(end, 0);

		self.frame.get_mut(self.accepted..).unwrap_or_default()
	}

	/// Accepts the octets that the last read filled into [`Self::wanted`], and
	/// moves to the next stage. A whole frame moves the assembler to the tag
	/// of the next frame.
	///
	/// # Errors
	///
	/// - [`TransportError::InvalidState`] -- the region of [`Self::wanted`] was not lent for this stage.
	/// - [`TransportError::InvalidMessage`] -- the length field is
	///   non-canonical, uses the BER indefinite form, or is wider than a
	///   `usize`. The first length octet refuses the last two.
	/// - [`TransportError::OperationFailed`] with
	///   [`TransportFailure::SizeExceeded`] -- the declared length passes the
	///   cap, before a byte of the content is wanted.
	pub(crate) fn advance(&mut self) -> TransportResult<Step> {
		let filled = self.accepted.saturating_add(self.stage.wanted());
		if self.frame.len() != filled {
			return Err(TransportError::InvalidState);
		}

		self.accepted = filled;

		let next = match &self.stage {
			Stage::Prefix => Stage::Length,
			Stage::Length => match LengthForm::try_from(self.length_first()?)? {
				LengthForm::Short(_) => self.admitted()?,
				LengthForm::Long(octets) => Stage::LongLength { octets },
			},
			Stage::LongLength { .. } => self.admitted()?,
			Stage::Content { .. } => {
				let frame = mem::take(&mut self.frame);
				self.accepted = 0;
				self.stage = Stage::Prefix;
				return Ok(Step::Done(frame));
			}
		};

		self.stage = next;
		Ok(Step::More)
	}

	/// Names `error`, the failure of the read that [`Self::wanted`] lent, by
	/// the stage it interrupts.
	///
	/// - Before the tag, an end of stream is a close between frames, [`TransportError::ConnectionClosed`].
	/// - After the tag, an end of stream truncates the frame, [`TransportError::InvalidMessage`].
	/// - Any other error passes through unchanged.
	pub(crate) fn classify(&self, error: TransportError) -> TransportError {
		match self.stage {
			Stage::Prefix => error.at_frame_boundary(),
			Stage::Length | Stage::LongLength { .. } | Stage::Content { .. } => error.inside_frame(),
		}
	}

	/// The first length octet, which follows the tag.
	///
	/// # Errors
	///
	/// - [`TransportError::InvalidState`] -- the frame holds no length octet yet.
	fn length_first(&self) -> TransportResult<u8> {
		self.frame.get(1).copied().ok_or(TransportError::InvalidState)
	}

	/// The stage of the content, once the cap admits the length field the
	/// frame holds.
	///
	/// # Errors
	///
	/// - The errors of [`FrameHeader::parse`] and [`FrameHeader::admit`].
	fn admitted(&self) -> TransportResult<Stage> {
		let length_octets = self.frame.get(2..).unwrap_or_default();
		let header = FrameHeader::parse(self.length_first()?, length_octets)?;
		let admitted = header.admit(self.cap)?;

		Ok(Stage::Content { header: admitted })
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
			assert!(matches!(LengthForm::try_from(first), Ok(LengthForm::Short(len)) if len == length));
		}
		cases {
			zero => (0x00, 0),
			most => (0x7F, 127),
		}
	}

	// Each case is (first length octet, further length octet count). The
	// widest long form counts as many octets as a `usize` holds.
	crate::tb_cases! {
		fn length_form_classifies_a_long_first_octet((first, count): (u8, usize)) {
			assert!(matches!(LengthForm::try_from(first), Ok(LengthForm::Long(len)) if len == count));
		}
		cases {
			one_octet => (0x81, 1),
			four_octets => (0x84, 4),
			widest => (0x80 | mem::size_of::<usize>() as u8, mem::size_of::<usize>()),
		}
	}

	// Each case is a first length octet that names a length field no reader
	// takes: the BER indefinite form, or one wider than any `usize`.
	crate::tb_cases! {
		fn length_form_refuses_a_first_octet_it_cannot_read(first: u8) {
			assert!(matches!(LengthForm::try_from(first), Err(TransportError::InvalidMessage)));
		}
		cases {
			indefinite => 0x80,
			nine_octets => 0x89,
			most => 0xFF,
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

	/// Fills the region `assembler` wants with `octets`, which hold exactly
	/// that many octets, and advances it.
	fn fed(assembler: &mut FrameAssembler, octets: &[u8]) -> TransportResult<Step> {
		assembler.wanted().copy_from_slice(octets);
		assembler.advance()
	}

	/// The frame that the reads of `stages` assemble under a cap of 256, one
	/// read per stage, or `None` when the stages end before the frame is
	/// whole.
	fn assembled(stages: &[&[u8]]) -> TransportResult<Option<Vec<u8>>> {
		assembled_by(&mut FrameAssembler::new(256), stages)
	}

	/// The frame that the reads of `stages` assemble on `assembler`, one read
	/// per stage, or `None` when the stages end before the frame is whole.
	fn assembled_by(assembler: &mut FrameAssembler, stages: &[&[u8]]) -> TransportResult<Option<Vec<u8>>> {
		for stage in stages {
			if let Step::Done(frame) = fed(assembler, stage)? {
				return Ok(Some(frame));
			}
		}

		Ok(None)
	}

	// Each case is the read of each stage of one frame. The frame assembles as
	// the octets it arrived as, in the short and the long form of its length.
	crate::tb_cases! {
		fn a_frame_assembles_as_it_arrived(stages: &[&[u8]]) -> TransportResult<()> {
			let arrived = stages.concat();
			assert_eq!(assembled(stages)?, Some(arrived));
			Ok(())
		}
		cases {
			short_form => &[&[0x30], &[0x02], &[0x01, 0x02]],
			long_form => &[&[0x30], &[0x81], &[0x80], &[0xAA; 128]],
			empty_content => &[&[0x05], &[0x00], &[]],
		}
	}

	/// The assembler admits the declared length under its cap before it
	/// wants a byte of the content, so the header alone refuses a length
	/// past the cap (CWE-770).
	#[test]
	fn a_length_past_the_cap_is_refused_before_the_content_is_wanted() -> TransportResult<()> {
		let mut assembler = FrameAssembler::new(16);
		fed(&mut assembler, &[0x30])?;
		fed(&mut assembler, &[0x82])?;

		let refused = fed(&mut assembler, &[0x02, 0x58]);
		assert!(matches!(
			refused,
			Err(TransportError::OperationFailed(TransportFailure::SizeExceeded))
		));
		Ok(())
	}

	/// The first length octet names the count of the octets that follow it,
	/// so the assembler refuses a length wider than a `usize` before it
	/// buffers one octet past the first.
	#[test]
	fn a_length_wider_than_a_usize_is_refused_at_its_first_octet() -> TransportResult<()> {
		let mut assembler = FrameAssembler::new(256);
		fed(&mut assembler, &[0x30])?;

		let refused = fed(&mut assembler, &[0xFF]);
		let invalid = matches!(refused, Err(TransportError::InvalidMessage));
		assert_eq!((invalid, assembler.frame.len()), (true, 2));
		Ok(())
	}

	/// A whole frame returns the assembler to the tag of the next frame, so
	/// one assembler frames each envelope of a stream in turn.
	#[test]
	fn one_assembler_frames_two_envelopes_in_a_row() -> TransportResult<()> {
		let mut assembler = FrameAssembler::new(256);
		let first = assembled_by(&mut assembler, &[&[0x30], &[0x02], &[0x01, 0x02]])?;
		let second = assembled_by(&mut assembler, &[&[0x04], &[0x01], &[0xAA]])?;

		let expected = (Some(vec![0x30, 0x02, 0x01, 0x02]), Some(vec![0x04, 0x01, 0xAA]));
		assert_eq!((first, second), expected);
		Ok(())
	}

	/// An end of stream before the tag falls between two frames, so it reads
	/// as a close.
	#[cfg(feature = "std")]
	#[test]
	fn an_eof_before_the_tag_is_a_close() {
		let assembler = FrameAssembler::new(16);
		let eof = TransportError::IoError(ErrorKind::UnexpectedEof.into());

		assert!(matches!(assembler.classify(eof), TransportError::ConnectionClosed));
	}

	/// An end of stream after the tag cuts a frame short, so it reads as a
	/// truncation.
	#[test]
	fn an_eof_inside_the_frame_is_a_truncation() -> TransportResult<()> {
		let mut assembler = FrameAssembler::new(16);
		fed(&mut assembler, &[0x30])?;

		let truncated = assembler.classify(TransportError::ConnectionClosed);
		assert!(matches!(truncated, TransportError::InvalidMessage));
		Ok(())
	}
}
