//! The frame body of a payload with no ASN.1 schema of its own.

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use crate::der::asn1::OctetString;
use crate::der::Sequence;
use crate::error::Result;
use crate::Beamable;

/// Application octets carried as a frame body: a SEQUENCE around one OCTET
/// STRING.
///
/// A frame body is DER, so raw bytes take this wrapper to travel. Peers on any
/// target read the same body through it.
///
/// # Examples
///
/// ```
/// # #[cfg(feature = "builder")]
/// # {
/// use tightbeam::builder::TypeBuilder;
/// use tightbeam::{decode, Opaque, Version};
///
/// let composed = Version::V0.compose::<Opaque>().with_id(b"raw").with_order(1);
/// let frame = composed.with_message(Opaque::new(*b"raw octets")?).build()?;
///
/// assert_eq!(decode::<Opaque>(frame.message())?.as_bytes(), b"raw octets");
/// # }
/// # Ok::<(), tightbeam::TightBeamError>(())
/// ```
#[derive(Beamable, Clone, Debug, PartialEq, Eq, Sequence)]
#[beam(min_version = "V0")]
pub struct Opaque {
	body: OctetString,
}

impl Opaque {
	/// Wrap `octets`.
	///
	/// # Errors
	///
	/// - [`crate::TightBeamError::SerializationError`] -- `octets` exceed the DER length limit.
	pub fn new(octets: impl Into<Vec<u8>>) -> Result<Self> {
		let body = OctetString::new(octets.into())?;
		Ok(Self { body })
	}

	/// The application octets.
	#[must_use]
	pub fn as_bytes(&self) -> &[u8] {
		self.body.as_bytes()
	}

	/// The application octets, by value.
	#[must_use]
	pub fn into_bytes(self) -> Vec<u8> {
		self.body.into_bytes()
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::testing::TestResult;
	use crate::{decode, encode};

	#[test]
	fn a_body_wraps_its_octets_in_one_sequence() -> TestResult {
		let body = encode(&Opaque::new([0xAB, 0xCD])?)?;
		assert_eq!(body, [0x30, 0x04, 0x04, 0x02, 0xAB, 0xCD]);
		Ok(())
	}

	#[test]
	fn a_body_round_trips_its_octets() -> TestResult {
		let body = Opaque::new(*b"payload")?;
		let decoded: Opaque = decode(&encode(&body)?)?;
		assert_eq!(decoded.as_bytes(), b"payload");
		assert_eq!(decoded.into_bytes(), b"payload");
		Ok(())
	}
}
