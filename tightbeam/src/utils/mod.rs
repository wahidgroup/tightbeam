//! The utility modules, and the DER encode, decode, and digest functions.

use crate::asn1::admission::DerAdmission;
use crate::error::TightBeamError;

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

pub mod basis_points;
pub mod marker;
pub mod task;
pub mod time;

pub use basis_points::{BasisPoints, BasisPointsOutOfRange};

#[cfg(feature = "hex")]
pub use ::hex_literal::hex;

/// Encode a value to DER format.
///
/// Every universal SET of the output holds its elements in DER order
/// (X.690 § 11.6). `der` 0.7 alone sorts a SET OF a CHOICE, such as the
/// `SignerInfos` of a countersigned `SignedData`, in another order, which the
/// decoders of this crate refuse.
///
/// # Errors
///
/// - [`TightBeamError::SerializationError`] -- `value` fails to encode.
///
/// # Examples
///
/// ```
/// let encoded = tightbeam::encode(&7u64)?;
/// assert_eq!(encoded, [0x02, 0x01, 0x07]);
/// # Ok::<(), tightbeam::TightBeamError>(())
/// ```
///
/// # Sources
///
/// - ITU-T X.690 (02/2021) § 11.6, set-of components:
///   <https://www.itu.int/rec/dologin_pub.asp?id=T-REC-X.690-202102-I%21%21PDF-E&lang=e&type=items#page=29>
#[inline]
pub fn encode<T: der::Encode>(value: &T) -> Result<Vec<u8>, TightBeamError> {
	let mut der = der::Encode::to_der(value)?;
	DerAdmission::arrange(&mut der)?;
	Ok(der)
}

/// Decode a DER value, such as a typed message from a frame body.
///
/// `content` is any borrowed byte source, such as `&[u8]`, `&Vec<u8>`, or
/// `&[u8; N]`. The borrow outlives the call so a decoded type may borrow from
/// those bytes. Every universal SET in `content` MUST hold its elements in
/// DER order (X.690 § 11.6), which the decode checks before it sorts one.
///
/// # Errors
///
/// - [`TightBeamError::SerializationError`] -- `content` is no DER encoding of
///   `T`, or a SET in it holds its elements out of DER order.
///
/// # Examples
///
/// ```
/// let encoded = tightbeam::encode(&7u64)?;
/// let decoded: u64 = tightbeam::decode(&encoded)?;
/// assert_eq!(decoded, 7);
/// # Ok::<(), tightbeam::TightBeamError>(())
/// ```
///
/// # Sources
///
/// - ITU-T X.690 (02/2021) § 11.6, set-of components:
///   <https://www.itu.int/rec/dologin_pub.asp?id=T-REC-X.690-202102-I%21%21PDF-E&lang=e&type=items#page=29>
#[inline]
pub fn decode<'a, T: der::Decode<'a>>(content: &'a (impl AsRef<[u8]> + ?Sized)) -> Result<T, TightBeamError> {
	let content = content.as_ref();
	DerAdmission::SetOrder.admit(content)?;
	Ok(der::Decode::from_der(content)?)
}

/// Compute the `DigestInfo` of `data` under the digest algorithm `D`.
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

	use crate::asn1::admission::fixtures::descending_attribute;
	use crate::cms::cert::x509::attr::Attribute;
	use crate::der::asn1::OctetStringRef;
	use crate::der::oid::ObjectIdentifier;
	use crate::der::ErrorKind;
	use crate::error::TightBeamError::SerializationError;

	#[test]
	fn data_driven_der_round_trip() -> Result<(), TightBeamError> {
		let oid_cases = [
			ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1"),
			ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.1"),
			ObjectIdentifier::new_unwrap("2.5.4.3"),
		];

		// The octet string cases vary in size and pattern.
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

	#[test]
	fn a_descending_set_is_refused() {
		let refused = decode::<Attribute>(&descending_attribute());
		let set_ordering = matches!(refused, Err(SerializationError(error)) if error.kind() == ErrorKind::SetOrdering);
		assert!(set_ordering);
	}
}
