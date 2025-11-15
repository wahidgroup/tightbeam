use crate::asn1::{Frame, Version};

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
