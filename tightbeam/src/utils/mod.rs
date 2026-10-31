//! The DER encode, decode, and digest functions, and the `hex!` macro of
//! `hex-literal`.

use crate::asn1::admission::DerAdmission;
use crate::error::TightBeamError;

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

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
	Ok(DerAdmission::SetOrder.decode(content.as_ref())?)
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
/// here, so the pieces reach a `DigestInfo` with no copy into one buffer.
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
	use crate::asn1::admission::fixtures::descending_attribute;
	use crate::cms::cert::x509::attr::Attribute;
	use crate::der::asn1::OctetStringRef;
	use crate::der::oid::db::{rfc4519, rfc5280, rfc5912};
	use crate::der::oid::ObjectIdentifier;
	use crate::der::ErrorKind;
	use crate::error::TightBeamError::SerializationError;
	use crate::testing::vectors::patterned;
	use crate::testing::TestResult;

	use super::*;

	// An OID encodes under its universal tag and decodes back to itself.
	crate::tb_cases! {
		fn an_oid_survives_a_der_round_trip(oid: ObjectIdentifier) -> TestResult {
			let enc = encode(&oid)?;
			assert_eq!(enc.first(), Some(&0x06));

			let dec: ObjectIdentifier = decode(&enc)?;
			assert_eq!(dec, oid);
			Ok(())
		}
		cases {
			rsa_encryption => rfc5912::RSA_ENCRYPTION,
			server_auth => rfc5280::ID_KP_SERVER_AUTH,
			common_name => rfc4519::COMMON_NAME,
		}
	}

	// The octet string cases vary in size and pattern.
	crate::tb_cases! {
		fn an_octet_string_survives_a_der_round_trip(data: Vec<u8>) -> TestResult {
			let oct = OctetStringRef::new(&data)?;
			let enc = encode(&oct)?;
			assert_eq!(enc.first(), Some(&0x04));

			let dec: OctetStringRef<'_> = decode(&enc)?;
			assert_eq!(dec.as_bytes(), data);
			Ok(())
		}
		cases {
			empty => b"".to_vec(),
			one_octet => b"a".to_vec(),
			word => b"hello".to_vec(),
			sentence => b"The quick brown fox jumps over the lazy dog".to_vec(),
			counting => patterned(64),
		}
	}

	/// The decode checks the order of each SET before it sorts one, so a
	/// descending set is refused as a SET ordering error.
	#[test]
	fn a_descending_set_is_refused() {
		let refused = decode::<Attribute>(&descending_attribute());
		let set_ordering = matches!(refused, Err(SerializationError(error)) if error.kind() == ErrorKind::SetOrdering);
		assert!(set_ordering);
	}
}
