//! The wire envelope of a handshake message, as the handshake drivers send it.
//!
//! Both handshake protocols carry their messages in the CMS containers of
//! [`TransportEnvelope`]. HPKE sends its hello as a `ContentInfo` of type
//! `id-data` and its reply as a `SignedData`, and the CMS handshake opens with
//! an `AuthEnvelopedData`. Both close with an `AuthEnvelopedData`.

use crate::transport::envelopes::TransportEnvelope;
use crate::transport::error::TransportError;
use crate::transport::handshake::HandshakeMessage;

#[cfg(any(
	feature = "transport-hpke",
	all(feature = "transport-multiplex", feature = "transport-cms")
))]
use crate::asn1::OctetString;
#[cfg(any(
	feature = "transport-hpke",
	all(feature = "transport-multiplex", feature = "transport-cms")
))]
use crate::transport::handshake::error::HandshakeError;

#[cfg(any(
	feature = "transport-hpke",
	all(feature = "transport-multiplex", feature = "transport-cms")
))]
mod point {
	pub use crate::crypto::common::typenum::Unsigned;
	pub use crate::crypto::sign::elliptic_curve::sec1::{CompressedPoint, CompressedPointSize};
	pub use crate::transport::handshake::HandshakeCurve;
}

#[cfg(any(
	feature = "transport-hpke",
	all(feature = "transport-multiplex", feature = "transport-cms")
))]
use point::*;

impl From<HandshakeMessage> for TransportEnvelope {
	fn from(message: HandshakeMessage) -> Self {
		match message {
			HandshakeMessage::SignedData(signed) => Self::SignedData(signed),
			HandshakeMessage::AuthEnvelopedData(enveloped) => Self::AuthEnvelopedData(enveloped),
			HandshakeMessage::Data(data) => Self::Data(data),
		}
	}
}

impl TryFrom<TransportEnvelope> for HandshakeMessage {
	type Error = TransportError;

	/// Handshake messages travel in one of the three handshake containers, so
	/// this conversion refuses any other envelope on the handshake path.
	fn try_from(envelope: TransportEnvelope) -> Result<Self, Self::Error> {
		match envelope {
			TransportEnvelope::SignedData(signed) => Ok(Self::SignedData(signed)),
			TransportEnvelope::AuthEnvelopedData(enveloped) => Ok(Self::AuthEnvelopedData(enveloped)),
			TransportEnvelope::Data(data) => Ok(Self::Data(data)),
			_ => Err(TransportError::InvalidMessage),
		}
	}
}

/// Fixed-width views of a DER `OctetString`.
#[cfg(any(
	feature = "transport-hpke",
	all(feature = "transport-multiplex", feature = "transport-cms")
))]
pub trait HandshakeOctets {
	/// Fixed `N`-byte view of a public wire value, such as a nonce.
	///
	/// # Errors
	///
	/// - [`HandshakeError::OctetStringLengthError`] -- the length differs from
	///   `N`, so a short or long value fails closed.
	fn to_byte_array<const N: usize>(&self) -> Result<[u8; N], HandshakeError>;

	/// The view of a point of the curve `C` in the compressed SEC 1 form, at
	/// the width of that form on `C` (SEC 1 v2.0 §2.3.3), as the HPKE hello,
	/// the HPKE reply, and each rekey leg carry it. This view reads the width
	/// alone, and [`PeerPoint::parse`] reads the form and decodes the point.
	///
	/// # Errors
	///
	/// - [`HandshakeError::OctetStringLengthError`] -- the length differs from the compressed width of `C`.
	///
	/// [`PeerPoint::parse`]: super::schedule::PeerPoint::parse
	fn to_compressed_point<C: HandshakeCurve>(&self) -> Result<CompressedPoint<C>, HandshakeError>;

	/// Fixed 32-byte view of an HPKE wire nonce or other public value.
	///
	/// # Errors
	///
	/// - [`HandshakeError::OctetStringLengthError`] -- the length differs from
	///   32, so a short or long nonce fails closed.
	fn to_32_byte_array(&self) -> Result<[u8; 32], HandshakeError> {
		self.to_byte_array::<32>()
	}
}

#[cfg(any(
	feature = "transport-hpke",
	all(feature = "transport-multiplex", feature = "transport-cms")
))]
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
