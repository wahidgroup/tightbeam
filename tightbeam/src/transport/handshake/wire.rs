//! Wire envelope mapping for the handshake drivers.
//!
//! Both handshake protocols share the CMS container grammar on the wire
//! ([`TransportEnvelope`]): ECIES tunnels its own message types inside
//! `SignedData`/`EnvelopedData`, while the CMS handshake exchanges the
//! containers themselves.

use crate::transport::envelopes::TransportEnvelope;
use crate::transport::error::TransportError;
use crate::transport::handshake::HandshakeMessage;

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
