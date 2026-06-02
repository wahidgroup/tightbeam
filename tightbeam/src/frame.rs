use crate::asn1::{Frame, Version};
#[cfg(feature = "digest")]
use crate::der::{Encode, EncodeValue, FixedTag, Length, Tag, Writer};
#[cfg(feature = "digest")]
use crate::Metadata;

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
