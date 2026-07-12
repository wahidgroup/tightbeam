use crate::asn1::{Frame, Version};
#[cfg(feature = "signature")]
use crate::der::asn1::ContextSpecificRef;
#[cfg(any(feature = "digest", feature = "signature"))]
use crate::der::{Encode, EncodeValue, FixedTag, Length, Tag, Writer};
#[cfg(feature = "signature")]
use crate::der::{TagMode, TagNumber};
#[cfg(feature = "signature")]
use crate::DigestInfo;
#[cfg(any(feature = "digest", feature = "signature"))]
use crate::Metadata;

#[cfg(all(not(feature = "std"), feature = "signature"))]
use alloc::vec::Vec;

/// Envelope-only view (version + metadata) used to compute Frame Integrity
/// (FI). The message field is excluded by construction: FI MUST be computed
/// over the envelope only. Borrows its fields so the builder and the verifier
/// share one zero-copy encoding, preventing the digest preimage from drifting.
#[cfg(feature = "digest")]
pub(crate) struct FrameIntegrityScaffold<'a> {
	pub(crate) version: &'a Version,
	pub(crate) metadata: &'a Metadata,
}

#[cfg(feature = "digest")]
impl FixedTag for FrameIntegrityScaffold<'_> {
	const TAG: Tag = Tag::Sequence;
}

#[cfg(feature = "digest")]
impl EncodeValue for FrameIntegrityScaffold<'_> {
	fn value_len(&self) -> crate::der::Result<Length> {
		self.version.encoded_len()? + self.metadata.encoded_len()?
	}

	fn encode_value(&self, encoder: &mut impl Writer) -> crate::der::Result<()> {
		self.version.encode(encoder)?;
		self.metadata.encode(encoder)?;
		Ok(())
	}
}

/// To-be-signed view of a [`Frame`]: the first four fields, with
/// `nonrepudiation` excluded by construction. Borrows the frame and reuses
/// each field's derived encoder so the TBS bytes cannot drift from the DER
/// encoding `#[derive(der::Sequence)]` produces for [`Frame`] -- the same
/// envelope-drift defense as [`FrameIntegrityScaffold`].
#[cfg(feature = "signature")]
pub(crate) struct TbsScaffold<'a> {
	pub(crate) version: &'a Version,
	pub(crate) metadata: &'a Metadata,
	pub(crate) message: &'a Vec<u8>,
	pub(crate) integrity: Option<&'a DigestInfo>,
}

#[cfg(feature = "signature")]
impl<'a> TbsScaffold<'a> {
	/// Mirrors the derive's encoding of `integrity`: context-specific tag 0,
	/// EXPLICIT mode.
	fn tagged_integrity(integrity: &'a DigestInfo) -> ContextSpecificRef<'a, DigestInfo> {
		ContextSpecificRef { tag_number: TagNumber::N0, tag_mode: TagMode::Explicit, value: integrity }
	}
}

#[cfg(feature = "signature")]
impl FixedTag for TbsScaffold<'_> {
	const TAG: Tag = Tag::Sequence;
}

#[cfg(feature = "signature")]
impl EncodeValue for TbsScaffold<'_> {
	fn value_len(&self) -> crate::der::Result<Length> {
		let mut len = (self.version.encoded_len()? + self.metadata.encoded_len()?)?;
		len = (len + self.message.encoded_len()?)?;

		if let Some(integrity) = self.integrity {
			len = (len + Self::tagged_integrity(integrity).encoded_len()?)?;
		}

		Ok(len)
	}

	fn encode_value(&self, encoder: &mut impl Writer) -> crate::der::Result<()> {
		self.version.encode(encoder)?;
		self.metadata.encode(encoder)?;
		self.message.encode(encoder)?;

		if let Some(integrity) = self.integrity {
			Self::tagged_integrity(integrity).encode(encoder)?;
		}

		Ok(())
	}
}

impl Frame {
	/// Validate that the frame's version is compatible with its metadata fields.
	/// This performs compile-time validation when used in const contexts.
	/// Returns true if valid, false if invalid (compile-time error).
	pub const fn validate_version_compatibility(&self) -> bool {
		let version = self.version;
		let metadata = &self.metadata;

		// Check each field against version capabilities
		// If a field is Some but the version doesn't allow it, return false
		let integrity_ok = metadata.integrity.is_none() || version.allows_integrity();
		let confidentiality_ok = metadata.confidentiality.is_none() || version.allows_confidentiality();
		let priority_ok = metadata.priority.is_none() || version.allows_priority();
		let lifetime_ok = metadata.lifetime.is_none() || version.allows_lifetime();
		let previous_frame_ok = metadata.previous_frame.is_none() || version.allows_previous_frame();
		let matrix_ok = metadata.matrix.is_none() || version.allows_matrix();

		integrity_ok && confidentiality_ok && priority_ok && lifetime_ok && previous_frame_ok && matrix_ok
	}

	/// Compile-time validation: ensures version supports fields that are present.
	/// Call this in a const context when constructing Frame manually to validate
	/// version compatibility at compile time.
	pub const fn const_validate_version_fields(version: Version, has_matrix: bool) -> bool {
		// Compile-time check: if matrix is present, version must support it
		!has_matrix || version.allows_matrix()
	}
}
