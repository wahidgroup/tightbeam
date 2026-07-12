//! Per-protocol wire envelope mapping for the TCP handshake drivers.
//!
//! Both handshake protocols share the CMS container grammar on the wire
//! ([`TransportEnvelope`]): ECIES tunnels its own message types inside
//! `SignedData`/`EnvelopedData`, while the CMS handshake exchanges the
//! containers themselves. These methods are the single place that knows
//! which container each protocol expects at each step, keeping the
//! transport drivers protocol-agnostic.

#[cfg(not(feature = "std"))]
use alloc::{boxed::Box, vec::Vec};

use crate::cms::enveloped_data::EnvelopedData;
use crate::cms::signed_data::SignedData;
use crate::der::{Decode, Encode};
use crate::transport::envelopes::TransportEnvelope;
use crate::transport::error::TransportError;
use crate::transport::handshake::HandshakeProtocolKind;

#[cfg(feature = "transport-ecies")]
use crate::transport::handshake::{ClientHello, ClientKeyExchange, ServerHandshake};

impl HandshakeProtocolKind {
	/// Wrap the client's first handshake message in its wire envelope.
	///
	/// ECIES starts with a signed ClientHello; CMS starts with the
	/// key-transport EnvelopedData itself.
	pub(crate) fn wrap_client_start(self, message: &[u8]) -> Result<TransportEnvelope, TransportError> {
		match self {
			#[cfg(feature = "transport-ecies")]
			Self::Ecies => {
				let client_hello = ClientHello::from_der(message)?;
				let signed_data: SignedData = (&client_hello).try_into().map_err(|_| TransportError::InvalidMessage)?;
				Ok(TransportEnvelope::SignedData(Box::new(signed_data)))
			}
			#[cfg(feature = "transport-cms")]
			Self::Cms => Ok(TransportEnvelope::EnvelopedData(Box::new(EnvelopedData::from_der(message)?))),
			#[cfg(not(feature = "transport-ecies"))]
			Self::Ecies => Err(TransportError::UnsupportedHandshakeProtocol(self)),
			#[cfg(not(feature = "transport-cms"))]
			Self::Cms => Err(TransportError::UnsupportedHandshakeProtocol(self)),
		}
	}

	/// Extract the raw handshake bytes the client orchestrator consumes from
	/// the server's response envelope.
	///
	/// Both protocols answer with SignedData; ECIES carries a ServerHandshake
	/// inside it, while the CMS orchestrator consumes the SignedData directly.
	pub(crate) fn unwrap_server_response(self, envelope: TransportEnvelope) -> Result<Vec<u8>, TransportError> {
		let signed_data = match envelope {
			TransportEnvelope::SignedData(sd) => sd,
			_ => return Err(TransportError::InvalidMessage),
		};

		match self {
			#[cfg(feature = "transport-ecies")]
			Self::Ecies => {
				let server_handshake: ServerHandshake =
					signed_data.as_ref().try_into().map_err(|_| TransportError::InvalidMessage)?;
				Ok(server_handshake.to_der()?)
			}
			#[cfg(feature = "transport-cms")]
			Self::Cms => Ok(signed_data.to_der()?),
			#[cfg(not(feature = "transport-ecies"))]
			Self::Ecies => Err(TransportError::UnsupportedHandshakeProtocol(self)),
			#[cfg(not(feature = "transport-cms"))]
			Self::Cms => Err(TransportError::UnsupportedHandshakeProtocol(self)),
		}
	}

	/// Wrap the client's follow-up handshake message in its wire envelope.
	///
	/// ECIES follows up with a key exchange (EnvelopedData); CMS follows up
	/// with the signed client Finished (SignedData).
	pub(crate) fn wrap_client_followup(self, message: &[u8]) -> Result<TransportEnvelope, TransportError> {
		match self {
			#[cfg(feature = "transport-ecies")]
			Self::Ecies => {
				let client_kex = ClientKeyExchange::from_der(message)?;
				let enveloped_data: EnvelopedData =
					(&client_kex).try_into().map_err(|_| TransportError::InvalidMessage)?;
				Ok(TransportEnvelope::EnvelopedData(Box::new(enveloped_data)))
			}
			#[cfg(feature = "transport-cms")]
			Self::Cms => Ok(TransportEnvelope::SignedData(Box::new(SignedData::from_der(message)?))),
			#[cfg(not(feature = "transport-ecies"))]
			Self::Ecies => Err(TransportError::UnsupportedHandshakeProtocol(self)),
			#[cfg(not(feature = "transport-cms"))]
			Self::Cms => Err(TransportError::UnsupportedHandshakeProtocol(self)),
		}
	}

	/// Extract the raw handshake bytes the server orchestrator consumes from
	/// a client envelope.
	///
	/// ECIES carries a ClientHello (SignedData) then a ClientKeyExchange
	/// (EnvelopedData) inside the containers; the CMS handshake consumes the
	/// containers directly.
	pub(crate) fn unwrap_client_request(self, envelope: &TransportEnvelope) -> Result<Vec<u8>, TransportError> {
		match (self, envelope) {
			#[cfg(feature = "transport-ecies")]
			(Self::Ecies, TransportEnvelope::SignedData(sd)) => Ok(ClientHello::try_from(sd.as_ref())
				.map_err(|_| TransportError::InvalidMessage)?
				.to_der()?),
			#[cfg(feature = "transport-ecies")]
			(Self::Ecies, TransportEnvelope::EnvelopedData(ed)) => Ok(ClientKeyExchange::try_from(ed.as_ref())
				.map_err(|_| TransportError::InvalidMessage)?
				.to_der()?),
			#[cfg(feature = "transport-cms")]
			(Self::Cms, TransportEnvelope::EnvelopedData(ed)) => Ok(ed.to_der()?),
			#[cfg(feature = "transport-cms")]
			(Self::Cms, TransportEnvelope::SignedData(sd)) => Ok(sd.to_der()?),
			#[cfg(not(feature = "transport-ecies"))]
			(Self::Ecies, _) => Err(TransportError::UnsupportedHandshakeProtocol(self)),
			#[cfg(not(feature = "transport-cms"))]
			(Self::Cms, _) => Err(TransportError::UnsupportedHandshakeProtocol(self)),
			_ => Err(TransportError::InvalidMessage),
		}
	}

	/// Wrap the server's handshake response in its wire envelope.
	///
	/// Both protocols answer with SignedData: ECIES wraps its
	/// ServerHandshake, CMS emits the signed server Finished directly.
	pub(crate) fn wrap_server_response(self, message: &[u8]) -> Result<TransportEnvelope, TransportError> {
		let signed_data = match self {
			#[cfg(feature = "transport-ecies")]
			Self::Ecies => {
				let server_handshake = ServerHandshake::from_der(message)?;
				(&server_handshake).try_into().map_err(|_| TransportError::InvalidMessage)?
			}
			#[cfg(feature = "transport-cms")]
			Self::Cms => SignedData::from_der(message)?,
			#[cfg(not(feature = "transport-ecies"))]
			Self::Ecies => return Err(TransportError::UnsupportedHandshakeProtocol(self)),
			#[cfg(not(feature = "transport-cms"))]
			Self::Cms => return Err(TransportError::UnsupportedHandshakeProtocol(self)),
		};

		Ok(TransportEnvelope::SignedData(Box::new(signed_data)))
	}
}
