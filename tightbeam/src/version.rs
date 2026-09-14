use crate::asn1::Version;

/// A Frame or Metadata field that only later protocol versions carry.
///
/// This enum is mapping for the version-to-field mapping in §5.6 of the
/// specification. An encoder MUST NOT emit a gated field below its
/// [`GatedField::since`] version, and a decoder MUST reject a frame
/// that carries one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GatedField {
	/// Message Integrity (MI) in `Metadata.integrity`.
	MessageIntegrity,
	/// Encryption parameters in `Metadata.confidentiality`.
	Confidentiality,
	/// Frame Integrity (FI) in `Frame.integrity`.
	FrameIntegrity,
	/// The signature in `Frame.nonrepudiation`.
	Nonrepudiation,
	/// Delivery priority in `Metadata.priority`.
	Priority,
	/// Time-to-live in `Metadata.lifetime`.
	Lifetime,
	/// The prior-frame digest in `Metadata.previous_frame`.
	PreviousFrame,
	/// The routing matrix in `Metadata.matrix`.
	Matrix,
}

impl GatedField {
	/// The first protocol version that carries this field.
	pub const fn since(self) -> Version {
		match self {
			GatedField::MessageIntegrity
			| GatedField::Confidentiality
			| GatedField::FrameIntegrity
			| GatedField::Nonrepudiation => Version::V1,
			GatedField::Priority | GatedField::Lifetime | GatedField::PreviousFrame => Version::V2,
			GatedField::Matrix => Version::V3,
		}
	}
}

impl core::fmt::Display for GatedField {
	/// The schema name of the field, qualified by the structure that holds it.
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		let name = match self {
			GatedField::MessageIntegrity => "Metadata.integrity",
			GatedField::Confidentiality => "Metadata.confidentiality",
			GatedField::FrameIntegrity => "Frame.integrity",
			GatedField::Nonrepudiation => "Frame.nonrepudiation",
			GatedField::Priority => "Metadata.priority",
			GatedField::Lifetime => "Metadata.lifetime",
			GatedField::PreviousFrame => "Metadata.previous_frame",
			GatedField::Matrix => "Metadata.matrix",
		};

		f.write_str(name)
	}
}

impl Version {
	/// Whether a frame at this version may carry `field`.
	pub const fn allows(self, field: GatedField) -> bool {
		self as u8 >= field.since() as u8
	}
}
