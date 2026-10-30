//! The fixed-width views of a DER `OctetString` that a handshake message
//! carries on the wire, such as a nonce.

#[cfg(any(feature = "transport-hpke", mux_rekey))]
pub use octets::HandshakeOctets;

/// The fixed-width views of a DER `OctetString` that the HPKE handshake and
/// the mux rekey read.
#[cfg(any(feature = "transport-hpke", mux_rekey))]
mod octets {
	use crate::asn1::OctetString;
	use crate::transport::handshake::error::HandshakeError;

	/// The fixed-width views of a DER `OctetString`.
	pub trait HandshakeOctets {
		/// The fixed `N`-byte view of a public wire value, such as a nonce.
		///
		/// # Errors
		///
		/// - [`HandshakeError::OctetStringLengthError`] -- the length differs
		///   from `N`, so a short or long value fails closed.
		fn to_byte_array<const N: usize>(&self) -> Result<[u8; N], HandshakeError>;

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
	}
}
