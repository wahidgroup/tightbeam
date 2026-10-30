//! The fixed-width views of a DER `OctetString` that a handshake message
//! carries on the wire, such as a nonce or a compressed curve point.

#[cfg(any(feature = "transport-hpke", mux_rekey))]
pub use octets::HandshakeOctets;

/// The fixed-width views of a DER `OctetString` that the HPKE handshake and
/// the mux rekey read.
#[cfg(any(feature = "transport-hpke", mux_rekey))]
mod octets {
	use crate::asn1::OctetString;
	use crate::crypto::common::typenum::Unsigned;
	use crate::crypto::sign::elliptic_curve::sec1::{CompressedPoint, CompressedPointSize};
	use crate::transport::handshake::error::HandshakeError;
	use crate::transport::handshake::HandshakeCurve;

	/// The fixed-width views of a DER `OctetString`.
	pub trait HandshakeOctets {
		/// The fixed `N`-byte view of a public wire value, such as a nonce.
		///
		/// # Errors
		///
		/// - [`HandshakeError::OctetStringLengthError`] -- the length differs
		///   from `N`, so a short or long value fails closed.
		fn to_byte_array<const N: usize>(&self) -> Result<[u8; N], HandshakeError>;

		/// The view of a point of the curve `C` in the compressed SEC 1 form,
		/// at the width of that form on `C` (SEC 1 v2.0 §2.3.3), as the HPKE
		/// hello, the HPKE reply, and each rekey leg carry it. This view reads
		/// the width alone, and the one parse of a peer ephemeral, in the
		/// [`ephemeral`] module, reads the form and decodes the point.
		///
		/// # Errors
		///
		/// - [`HandshakeError::OctetStringLengthError`] -- the length differs
		///   from the compressed width of `C`.
		///
		/// [`ephemeral`]: super::super::ephemeral
		fn to_compressed_point<C: HandshakeCurve>(&self) -> Result<CompressedPoint<C>, HandshakeError>;

		/// The fixed 32-byte view of an HPKE wire nonce or other public value.
		///
		/// # Errors
		///
		/// - [`HandshakeError::OctetStringLengthError`] -- the length differs
		///   from 32, so a short or long nonce fails closed.
		fn to_32_byte_array(&self) -> Result<[u8; 32], HandshakeError> {
			self.to_byte_array::<32>()
		}
	}

	impl HandshakeOctets for OctetString {
		fn to_byte_array<const N: usize>(&self) -> Result<[u8; N], HandshakeError> {
			let bytes = self.as_bytes();
			let mut out = [0u8; N];
			if bytes.len() != out.len() {
				return Err(HandshakeError::OctetStringLengthError((bytes.len(), out.len()).into()));
			}

			out.copy_from_slice(bytes);
			Ok(out)
		}

		fn to_compressed_point<C: HandshakeCurve>(&self) -> Result<CompressedPoint<C>, HandshakeError> {
			let octets = self.as_bytes();
			let point = CompressedPoint::<C>::from_exact_iter(octets.iter().copied());
			let width = (octets.len(), CompressedPointSize::<C>::USIZE);
			point.ok_or_else(|| HandshakeError::OctetStringLengthError(width.into()))
		}
	}
}
