use crate::asn1::Version;

/// Version capability methods.
/// This is the single source of truth for version-to-field mapping.
/// The specification lives here with Version, and builders use these methods.
/// All methods are const to enable compile-time evaluation.
impl Version {
	/// Whether this version allows integrity (V1+)
	pub const fn allows_integrity(self) -> bool {
		matches!(self, Version::V1 | Version::V2 | Version::V3)
	}

	/// Whether this version allows confidentiality (V1+)
	pub const fn allows_confidentiality(self) -> bool {
		matches!(self, Version::V1 | Version::V2 | Version::V3)
	}

	/// Whether this version allows priority (V2+)
	pub const fn allows_priority(self) -> bool {
		matches!(self, Version::V2 | Version::V3)
	}

	/// Whether this version allows lifetime (V2+)
	pub const fn allows_lifetime(self) -> bool {
		matches!(self, Version::V2 | Version::V3)
	}

	/// Whether this version allows previous_frame (V2+)
	pub const fn allows_previous_frame(self) -> bool {
		matches!(self, Version::V2 | Version::V3)
	}

	/// Whether this version allows matrix (V3+)
	pub const fn allows_matrix(self) -> bool {
		matches!(self, Version::V3)
	}
}
