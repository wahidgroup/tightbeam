use crate::asn1::Version;

#[cfg(feature = "builder")]
use crate::builder::FrameBuilder;
#[cfg(feature = "builder")]
use crate::Message;

/// A Frame or Metadata field that only later protocol versions carry.
///
/// This enum is the version-to-field mapping of §5.6 of the specification.
/// An encoder MUST NOT emit a gated field below its [`GatedField::since`]
/// version, and a decoder MUST reject a frame that carries one. A frame in
/// memory refuses such a field with [`UnsupportedField`].
///
/// [`UnsupportedField`]: crate::TightBeamError::UnsupportedField
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
	/// The prior-frame digest in `Metadata.previousFrame`.
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
			GatedField::PreviousFrame => "Metadata.previousFrame",
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

	/// The later of this version and `other`, in protocol order.
	///
	/// The method is `const`, so the `Beamable` derive combines two minimum
	/// versions of a message type in its `MIN_VERSION` constant through it.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::Version;
	///
	/// const LATER: Version = Version::V1.later(Version::V2);
	/// assert_eq!(LATER, Version::V2);
	/// assert_eq!(Version::V3.later(Version::V0), Version::V3);
	/// ```
	#[must_use]
	pub const fn later(self, other: Self) -> Self {
		if other as u8 > self as u8 {
			other
		} else {
			self
		}
	}

	/// Start a [`FrameBuilder`] for message type `T` at this version.
	///
	/// This is the method form of the `compose!` macro, for contexts
	/// where a macro cannot be used (inside another macro definition).
	#[cfg(feature = "builder")]
	pub fn compose<T: Message>(self) -> FrameBuilder<T> {
		FrameBuilder::from(self)
	}
}

#[cfg(test)]
mod tests {
	use crate::asn1::Version;

	// The later of two versions is the one later in protocol order, in either
	// argument order.
	crate::tb_cases! {
		fn the_later_of_two_versions_is_later_in_protocol_order((first, second, later): (Version, Version, Version)) {
			assert_eq!(first.later(second), later);
		}
		cases {
			the_receiver_is_later => (Version::V2, Version::V1, Version::V2),
			the_argument_is_later => (Version::V0, Version::V3, Version::V3),
			both_are_one_version => (Version::V1, Version::V1, Version::V1),
		}
	}
}
