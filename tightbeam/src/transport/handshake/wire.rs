//! Wire envelope mapping for the handshake drivers.
//!
//! Both handshake protocols share the CMS container grammar on the wire
//! ([`TransportEnvelope`]): ECIES tunnels its own message types inside
//! `SignedData`/`EnvelopedData`, while the CMS handshake exchanges the
//! containers themselves.

use crate::transport::envelopes::TransportEnvelope;
use crate::transport::error::TransportError;
use crate::transport::handshake::HandshakeMessage;

#[cfg(any(
	feature = "transport-ecies",
	all(feature = "transport-multiplex", feature = "transport-cms")
))]
use crate::asn1::OctetString;
#[cfg(any(
	feature = "transport-ecies",
	all(feature = "transport-multiplex", feature = "transport-cms")
))]
use crate::transport::handshake::error::HandshakeError;

impl From<HandshakeMessage> for TransportEnvelope {
	fn from(message: HandshakeMessage) -> Self {
		match message {
			HandshakeMessage::SignedData(signed) => Self::SignedData(signed),
			HandshakeMessage::EnvelopedData(enveloped) => Self::EnvelopedData(enveloped),
		}
	}
}

impl TryFrom<TransportEnvelope> for HandshakeMessage {
	type Error = TransportError;

	/// Handshake messages travel in one of the two CMS containers. Any other
	/// envelope on the handshake path is refused.
	fn try_from(envelope: TransportEnvelope) -> Result<Self, Self::Error> {
		match envelope {
			TransportEnvelope::SignedData(signed) => Ok(Self::SignedData(signed)),
			TransportEnvelope::EnvelopedData(enveloped) => Ok(Self::EnvelopedData(enveloped)),
			_ => Err(TransportError::InvalidMessage),
		}
	}
}

/// Fixed-width views of a DER `OctetString`.
#[cfg(any(
	feature = "transport-ecies",
	all(feature = "transport-multiplex", feature = "transport-cms")
))]
pub trait HandshakeOctets {
	/// Fixed 32-byte view of an ECIES wire nonce or other public value.
	///
	/// # Errors
	///
	/// - [`HandshakeError::OctetStringLengthError`] on any other length, so a
	///   short or long nonce fails closed
	fn to_32_byte_array(&self) -> Result<[u8; 32], HandshakeError>;

	/// Copy the 32 bytes into `out`, which may be a wiping buffer, so a key
	/// never passes through a plain array on the way.
	///
	/// # Errors
	///
	/// - [`HandshakeError::OctetStringLengthError`] on any other length
	fn copy_to_32_byte_array(&self, out: &mut [u8; 32]) -> Result<(), HandshakeError>;
}

#[cfg(any(
	feature = "transport-ecies",
	all(feature = "transport-multiplex", feature = "transport-cms")
))]
impl HandshakeOctets for OctetString {
	fn to_32_byte_array(&self) -> Result<[u8; 32], HandshakeError> {
		let mut out = [0u8; 32];
		self.copy_to_32_byte_array(&mut out)?;
		Ok(out)
	}

	fn copy_to_32_byte_array(&self, out: &mut [u8; 32]) -> Result<(), HandshakeError> {
		let bytes = self.as_bytes();
		if bytes.len() != out.len() {
			return Err(HandshakeError::OctetStringLengthError((bytes.len(), out.len()).into()));
		}

		out.copy_from_slice(bytes);
		Ok(())
	}
}
