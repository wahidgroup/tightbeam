//! Utility modules and functions

use crate::error::TightBeamError;

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

// Submodules
pub mod basis_points;
pub mod marker;
pub mod math;
pub mod task;
pub mod time;

pub use basis_points::{BasisPoints, BasisPointsOutOfRange};

// Re-exports
#[cfg(feature = "hex")]
pub use ::hex_literal::hex;

/// Encode a value to DER format
#[inline]
pub fn encode<T: der::Encode>(value: &T) -> Result<Vec<u8>, TightBeamError> {
	Ok(der::Encode::to_der(value)?)
}

/// Decode a DER value, such as a typed message from a frame body.
///
/// `content` is any borrowed byte source, such as `&[u8]`, `&Vec<u8>`, or
/// `&[u8; N]`. The borrow outlives the call so a decoded type may borrow from
/// those bytes.
#[inline]
pub fn decode<'a, T: der::Decode<'a>>(content: &'a (impl AsRef<[u8]> + ?Sized)) -> Result<T, TightBeamError> {
	Ok(der::Decode::from_der(content.as_ref())?)
}

/// Compute a digest of the provided data using the specified algorithm.
#[cfg(feature = "digest")]
#[inline]
pub fn digest<D: digest::Digest + crate::der::oid::AssociatedOid>(
	data: impl AsRef<[u8]>,
) -> Result<crate::asn1::DigestInfo, TightBeamError> {
	let mut hasher = D::new();
	hasher.update(data.as_ref());
	digest_info::<D>(hasher)
}

/// Finalize `hasher` into the [`DigestInfo`] that names its algorithm.
///
/// Callers whose preimage arrives in pieces stream it into `hasher` and end
/// here, so no caller has to concatenate a preimage into one buffer to get a
/// `DigestInfo` back.
///
/// [`DigestInfo`]: crate::asn1::DigestInfo
#[cfg(feature = "digest")]
pub(crate) fn digest_info<D: digest::Digest + crate::der::oid::AssociatedOid>(
	hasher: D,
) -> Result<crate::asn1::DigestInfo, TightBeamError> {
	let algorithm = crate::asn1::AlgorithmIdentifier { oid: D::OID, parameters: None };
	let digest = hasher.finalize();
	let digest_octet_string = crate::asn1::OctetString::new(&digest[..])?;
	Ok(crate::asn1::DigestInfo { algorithm, digest: digest_octet_string })
}

#[cfg(test)]
mod tests {
	use super::*;

	use crate::der::asn1::OctetStringRef;
	use crate::der::oid::ObjectIdentifier;

	#[test]
	fn data_driven_der_round_trip() -> Result<(), TightBeamError> {
		// OID cases
		let oid_cases = [
			ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1"),
			ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.1"),
			ObjectIdentifier::new_unwrap("2.5.4.3"),
		];

		// Octet string cases (varied sizes/patterns)
		let octet_cases: &[&[u8]] = &[
			b"",
			b"a",
			b"hello",
			b"The quick brown fox jumps over the lazy dog",
			&(0u16..64).map(|v| (v % 251) as u8).collect::<Vec<u8>>(),
		];

		for oid in oid_cases {
			let enc = encode(&oid)?;
			assert!(!enc.is_empty());
			assert_eq!(enc[0], 0x06);

			let dec: ObjectIdentifier = decode(&enc)?;
			assert_eq!(dec, oid);
		}

		for data in octet_cases {
			let oct = OctetStringRef::new(data)?;
			let enc = encode(&oct)?;
			assert_eq!(enc[0], 0x04);

			let dec: OctetStringRef<'_> = decode(&enc)?;
			assert_eq!(dec.as_bytes(), *data);
		}

		Ok(())
	}
}
